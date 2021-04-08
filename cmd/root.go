package cmd

import (
	"context"
	"fmt"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"github.com/spf13/cobra"
	"github.com/xanzy/go-gitlab"
	"os"
	"strings"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

type OktaGroup struct {
	ID    string
	Name  string
	Users []string
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "psync",
	Short: "Sync Okta groups permissions",
	Long:  `Automatically assign new groupMembers Gitlab groups permissions based on their Okta profile`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize Okta Client
		ctx, client, err := okta.NewClient(context.Background(),
			okta.WithOrgUrl(viper.GetString("okta.client.orgUrl")),
			okta.WithToken(viper.GetString("okta.client.token")),
			okta.WithRequestTimeout(viper.GetInt64("okta.client.requestTimeout")),
			okta.WithRateLimitMaxRetries(viper.GetInt32("okta.client.rateLimit.maxRetries")))
		cobra.CheckErr(err)

		// Initialize Gitlab Client
		gitlabClt, err := gitlab.NewBasicAuthClient(viper.GetString("gitlab.username"),
			viper.GetString("gitlab.password"),
			gitlab.WithBaseURL(viper.GetString("gitlab.baseUrl")))
		cobra.CheckErr(err)

		// Fetch the group members of the Okta groups that start with dev_
		oktaGroups, err := getOktaDevGroups(ctx, client)
		cobra.CheckErr(err)

		// Fetch Gitlab group AFKL-MCP members with access level < 50
		afklMembers, _ := getGitlabGroupMembers(gitlabClt, "AFKL-MCP")
		// Parse out afkl-mcp group members identity
		afklUids := make([]string, len(afklMembers))
		for i, m := range afklMembers {
			afklUids[i] = m.GroupSAMLIdentity.ExternUID
		}

		for _, g := range oktaGroups {
			// Fetch Gitlab developer group members
			// Find each member in afkl-mcp group and extract the identity
			glabgroup, grID := getGitlabGroupMembers(gitlabClt, g.Name)
			glabgroupUids := make([]string, 0, len(glabgroup))
			for _, glm := range glabgroup {
				for _, v := range afklMembers {
					if v.ID == glm.ID && v.GroupSAMLIdentity != nil {
						glabgroupUids = append(glabgroupUids, v.GroupSAMLIdentity.ExternUID)
					}
				}
			}
			// Identify Okta group members that are part of AFKL-MCP Gitlab group
			intersect := Intersection(g.Users, afklUids)
			// Find the members who are not assigned to the Gitlab developer group yet
			diff := Difference(intersect, glabgroupUids)
			// Assign the users to the Gitlab dev group with developer permissions level
			for _, x := range diff {
				var perm = gitlab.DeveloperPermissions
				for _, y := range afklMembers {
					if x == y.GroupSAMLIdentity.ExternUID {
						mem, _, err := gitlabClt.GroupMembers.AddGroupMember(grID, &gitlab.AddGroupMemberOptions{
							UserID:      &y.ID,
							AccessLevel: &perm,
						})
						cobra.CheckErr(err)
						fmt.Printf("%+v", mem)
						if mem.GroupSAMLIdentity != nil {
							fmt.Printf("%+v", mem.GroupSAMLIdentity)
						}
					}
				}
			}
		}
	},
}

// List only okta groups with dev_ in the name
func getOktaDevGroups(ctx context.Context, ctl *okta.Client) (groups []OktaGroup, err error) {
	oktaGroups, _, err := ctl.Group.ListGroups(ctx, &query.Params{
		Q: "dev_",
	})
	cobra.CheckErr(err)
	for _, g := range oktaGroups {
		gr := OktaGroup{ID: g.Id, Name: strings.Split(g.Profile.Name, "dev_")[1], Users: []string{}}
		// Fetch and store the group users
		users, _, err := ctl.Group.ListGroupUsers(ctx, g.Id, nil)
		cobra.CheckErr(err)

		for _, u := range users {
			gr.Users = append(gr.Users, u.Id)
		}
		groups = append(groups, gr)
	}
	return
}

func getGitlabGroupMembers(clt *gitlab.Client, name string) (members []*gitlab.GroupMember, id int) {
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

// Intersection of two sets
// Used to identify which group members exist both in an okta group and afkl-mcp group
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

// Difference of two sets
// Used to identify which users in the afkl-mcp group haven't been granted access to the given dev group
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
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config.yaml", "config file (default is $HOME/.psync.yaml)")

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
