package cmd

import (
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"context"
	"fmt"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"github.com/spf13/cobra"
	"github.com/xanzy/go-gitlab"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"log"
	"os"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

type OktaGroup struct {
	ID            string
	Name          string
	Users         []string
	Deprovisioned []string
}

type GitlabMember struct {
	User *gitlab.GroupMember
	SAMLID string
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "psync",
	Short: "Sync Okta groups permissions",
	Long:  `Automatically assign new groupMembers Gitlab groups permissions based on their Okta profile`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create the GCP client
		gcpCtx := context.Background()
		gcpClient, err := secretmanager.NewClient(gcpCtx)
		if err != nil {
			log.Fatal(err)
		}
		req := &secretmanagerpb.AccessSecretVersionRequest{Name: viper.GetString("OKTA_SECRET")}
		oktaToken, err := gcpClient.AccessSecretVersion(gcpCtx, req)
		if err != nil {
			log.Fatal(err)
		}
		// Initialize Okta Client
		ctx, client, err := okta.NewClient(context.Background(),
			okta.WithOrgUrl(viper.GetString("OKTA_ORG_URL")),
			okta.WithToken(string(oktaToken.Payload.Data)),
			okta.WithRequestTimeout(45),
			okta.WithRateLimitMaxRetries(3))
		cobra.CheckErr(err)

		req = &secretmanagerpb.AccessSecretVersionRequest{Name: viper.GetString("GITLAB_SECRET")}
		gitlabToken, err := gcpClient.AccessSecretVersion(gcpCtx, req)
		if err != nil {
			log.Fatal(err)
		}

		// Initialize Gitlab Client
		gitlabClt, err := gitlab.NewClient(string(gitlabToken.Payload.Data))
		cobra.CheckErr(err)

		// Fetch the group members of the Okta groups that start with dev_
		oktaGroups, err := GetOktaDevGroups(ctx, client)
		cobra.CheckErr(err)

		// Fetch Gitlab group AFKL-MCP members with access level < 50
		afklMembers, _ := GetGitlabGroupMembers(gitlabClt, "AFKL-MCP")
		// Parse out afkl-mcp group members identities
		afklUids := make([]string, len(afklMembers))
		for i, m := range afklMembers {
			if m.GroupSAMLIdentity != nil {
				afklUids[i] = m.GroupSAMLIdentity.ExternUID
			}
		}

		fmt.Println("Syncing okta dev_ groups ...")

		for _, g := range oktaGroups {
			// Fetch Gitlab dev group members, find each member in afkl-mcp group and extract their identity
			glabgroup, grID := GetGitlabGroupMembers(gitlabClt, g.Name)
			glabgroupMembers := make([]GitlabMember, 0, len(glabgroup))
			glabgroupUids := make([]string, 0, len(glabgroup))
			for _, glm := range glabgroup {
				for _, v := range afklMembers {
					// Check if SAML identity is not nil. If it is, something went wrong when user was added to AFKL group
					// Users without a SAML identity cannot be matched with Okta users (!)
					if v.ID == glm.ID && v.GroupSAMLIdentity != nil {
						glabgroupUids = append(glabgroupUids, v.GroupSAMLIdentity.ExternUID)
						glabgroupMembers = append(glabgroupMembers, GitlabMember{
							User:   glm,
							SAMLID: v.GroupSAMLIdentity.ExternUID,
						})
					}
				}
			}
			// Identify Okta group members that are part of AFKL-MCP Gitlab group
			oktaUsersInGitlab := Intersection(g.Users, afklUids)
			// Find the members who are not assigned to the Gitlab developer group yet
			usersToAdd := Difference(oktaUsersInGitlab, glabgroupUids)
			if len(usersToAdd) > 0 {
				fmt.Printf("Adding %d members to %s:\n", len(usersToAdd), g.Name)
			} else {
				fmt.Printf("No members to add to %s.\n", g.Name)
			}
			// Assign the users to the Gitlab dev group with developer permissions level
			for _, x := range usersToAdd {
				var perm = gitlab.DeveloperPermissions
				for _, y := range afklMembers {
					if x == y.GroupSAMLIdentity.ExternUID {
						mem, _, err := gitlabClt.GroupMembers.AddGroupMember(grID, &gitlab.AddGroupMemberOptions{
							UserID:      &y.ID,
							AccessLevel: &perm,
						})
						cobra.CheckErr(err)
						fmt.Printf("Added %+v\n", mem)
					}
				}
			}
			// Find deprovisioned or suspended Okta group users who still have access to the Gitlab group
			usersToRemove := Intersection(g.Deprovisioned, glabgroupUids)
			if len(usersToRemove) > 0 {
				fmt.Printf("Removing %d members from %s:\n", len(usersToRemove), g.Name)
			} else {
				fmt.Printf("No members to remove from %s.\n", g.Name)
			}
			// Remove deprovisioned or suspended users from the gitlab dev group
			for _, id := range usersToRemove {
				for _, member := range glabgroupMembers {
					if id == member.SAMLID {
						_, err := gitlabClt.GroupMembers.RemoveGroupMember(grID, member.User.ID)
						cobra.CheckErr(err)
						fmt.Printf("Removed %+v\n", member.User)
					}
				}
			}
		}
		fmt.Println("Sync completed successfully.")
	},
}

// GetOktaDevGroups finds and returns only the okta groups with dev_ in the name
func GetOktaDevGroups(ctx context.Context, ctl *okta.Client) (groups []OktaGroup, err error) {
	oktaGroups, _, err := ctl.Group.ListGroups(ctx, &query.Params{
		Q: "dev_",
	})
	cobra.CheckErr(err)
	for _, g := range oktaGroups {
		gr := OktaGroup{ID: g.Id, Name: strings.Split(g.Profile.Name, "dev_")[1], Users: []string{}, Deprovisioned: []string{}}
		// Fetch and store the group users
		users, _, err := ctl.Group.ListGroupUsers(ctx, g.Id, nil)
		cobra.CheckErr(err)

		for _, u := range users {
			if u.Status == "DEPROVISIONED" || u.Status == "SUSPENDED" {
				gr.Deprovisioned = append(gr.Deprovisioned, u.Id)
			} else {
				gr.Users = append(gr.Users, u.Id)
			}

		}
		groups = append(groups, gr)
	}
	return
}

// GetGitlabGroupMembers given a (part of) group name finds the group in Gitlab.
// Returns the group members and the group ID.
func GetGitlabGroupMembers(clt *gitlab.Client, name string) (members []*gitlab.GroupMember, id int) {
	groups, _, err := clt.Groups.ListGroups(&gitlab.ListGroupsOptions{
		Search: &name,
	})
	cobra.CheckErr(err)
	// Gitlab search returns a slice of len 1, so we take the ID of the 0 element
	id = groups[0].ID
	// List the group members
	users, _, err := clt.Groups.ListAllGroupMembers(id, &gitlab.ListGroupMembersOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100},
	})
	cobra.CheckErr(err)
	// Take only those with developer access level or less
	for _, u := range users {
		if u.AccessLevel < 50 {
			members = append(members, u)
		}
	}
	return
}

// Intersection returns the intersection of two sets.
// Used to identify which group members exist both in the okta developers group and the afkl-mcp group.
func Intersection(a, b []string) (c []string) {
	m := make(map[string]bool)

	for _, item := range a {
		m[item] = true
	}

	for _, item := range b {
		if _, ok := m[item]; ok {
			c = append(c, item)
		}
	}
	return
}

// Difference returns the difference of two sets.
// Used to identify which users in the afkl-mcp group haven't been granted access to the given dev group in Gitlab.
func Difference(a, b []string) (c []string) {
	m := make(map[string]bool)

	for _, item := range b {
		m[item] = true
	}

	for _, item := range a {
		if _, ok := m[item]; !ok {
			c = append(c, item)
		}
	}
	return
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", ".env.yaml", "config file (default is $HOME/.psync.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		cobra.CheckErr(err)

		// Search config in home directory with Name ".psync" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".psync")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		_, _ = fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
