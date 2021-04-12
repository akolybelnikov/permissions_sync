// Package psync implements permission sync between Okta and Gitlab dev groups
package psync

import (
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"context"
	"fmt"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xanzy/go-gitlab"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"net/http"
	"strings"
)

type oktaGroup struct {
	ID    string
	Name  string
	Users []string
}

// Psync implements a Google Cloud Function for the package
func Psync(w http.ResponseWriter, r *http.Request) {
	// Read in environment variables that match
	viper.AutomaticEnv()
	// Create the GCP client
	gcpCtx := context.Background()
	gcpClient, err := secretmanager.NewClient(gcpCtx)
	cobra.CheckErr(err)

	req := &secretmanagerpb.AccessSecretVersionRequest{Name: viper.GetString("OKTA_SECRET")}
	oktaToken, err := gcpClient.AccessSecretVersion(gcpCtx, req)
	cobra.CheckErr(err)

	// Initialize Okta Client
	ctx, client, err := okta.NewClient(context.Background(),
		okta.WithOrgUrl(viper.GetString("OKTA_ORG_URL")),
		okta.WithToken(string(oktaToken.Payload.Data)),
		okta.WithRequestTimeout(45),
		okta.WithRateLimitMaxRetries(3))
	cobra.CheckErr(err)

	req = &secretmanagerpb.AccessSecretVersionRequest{Name: viper.GetString("GITLAB_SECRET")}
	gitlabToken, err := gcpClient.AccessSecretVersion(gcpCtx, req)
	cobra.CheckErr(err)

	// Initialize Gitlab Client
	gitlabClt, err := gitlab.NewClient(string(gitlabToken.Payload.Data))
	cobra.CheckErr(err)

	// Fetch the group members of the Okta groups that start with dev_
	oktaGroups, err := getOktaDevGroups(ctx, client)
	cobra.CheckErr(err)

	// Fetch Gitlab group AFKL-MCP members with access level < 50
	afklMembers, _ := getGitlabGroupMembers(gitlabClt, "AFKL-MCP")
	// Parse out afkl-mcp group members identities
	afklUids := make([]string, len(afklMembers))
	for i, m := range afklMembers {
		if m.GroupSAMLIdentity != nil {
			afklUids[i] = m.GroupSAMLIdentity.ExternUID
		}
	}

	fmt.Println("Test: printing okta dev group names")

	for _, g := range oktaGroups {
		fmt.Println(g.Name)
		// Fetch Gitlab dev group members, find each member in afkl-mcp group and extract their identity
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
		intersect := getSetIntersection(g.Users, afklUids)
		// Find the members who are not assigned to the Gitlab developer group yet
		diff := getSetDifference(intersect, glabgroupUids)
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
}

// Finds and returns only the okta groups with dev_ in the name
func getOktaDevGroups(ctx context.Context, ctl *okta.Client) (groups []oktaGroup, err error) {
	oktaGroups, _, err := ctl.Group.ListGroups(ctx, &query.Params{
		Q: "dev_",
	})
	cobra.CheckErr(err)
	for _, g := range oktaGroups {
		gr := oktaGroup{ID: g.Id, Name: strings.Split(g.Profile.Name, "dev_")[1], Users: []string{}}
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

// Returns the group members and the group ID.
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

// Used to identify which group members exist both in the okta developers group and the afkl-mcp group.
func getSetIntersection(a, b []string) (c []string) {
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

// Used to identify which users in the afkl-mcp group haven't been granted access to the given dev group in Gitlab.
func getSetDifference(a, b []string) (c []string) {
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
