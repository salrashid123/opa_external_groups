package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
	cloudidentity "google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

var (
	cisvc       *cloudidentity.Service
	redisClient *redis.Client

	useRedis            = flag.Bool("useRedis", false, "Use redis cache")
	useCloudIdentityAPI = flag.Bool("useCloudIdentityAPI", false, "Use mock Groups")
	tlsCert             = flag.String("tlsCert", "../certs/server.crt", "Public x509")
	tlsKey              = flag.String("tlsKey", "../certs/server.key", "Private Key")
	mocks               = map[string]groupsStruct{
		"alice@domain.com": {
			Groups: []string{"securitygroup1@domain.com", "group_of_groups_1@domain.com", "group8_10@domain.com", "group4_7@domain.com", "deniedgcs@domain.com", "all_users_group@domain.com"},
		},
		"bob@domain.com": {
			Groups: []string{"all_users_group@domain.com"},
		},
	}
)

// this really should be a signed JWT that upstream can validate
type groupsStruct struct {
	Groups []string `json:"groups"`
}

const (
	cachInSeconds = 60
)

func posthandler(w http.ResponseWriter, r *http.Request) {

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("Error reading body: %v\n", err)
		http.Error(w, "can't read body", http.StatusInternalServerError)
		return
	}

	s := strings.ReplaceAll(string(body), "\"", "")
	query := fmt.Sprintf("member_key_id=='%s' && 'cloudidentity.googleapis.com/groups.discussion_forum' in labels", s)

	ctx := context.Background()
	groups := []string{}
	gr := &groupsStruct{}

	if !*useRedis {

		if !*useCloudIdentityAPI {
			fmt.Printf("Using Mocks\n")
			if g, ok := mocks[s]; ok {
				groups = g.Groups
			}
		} else {
			err = cisvc.Groups.Memberships.SearchTransitiveGroups("groups/-").Query(query).Pages(ctx, func(g *cloudidentity.SearchTransitiveGroupsResponse) error {
				for _, m := range g.Memberships {
					groups = append(groups, m.GroupKey.Id)
				}
				return nil
			})
			if err != nil {
				fmt.Printf("%v", err)
				http.Error(w, "Error happened in JSON marshal. Er", http.StatusInternalServerError)
			}
		}

		fmt.Printf("User [%s] --> %s\n", s, groups)

		gr.Groups = groups
	} else {

		pong, err := redisClient.Ping().Result()
		if err != nil {
			fmt.Printf("Redis status Error%v", pong)
		}

		gg, err := redisClient.Get(s).Result()
		if err == redis.Nil {
			fmt.Println("no value found, reading group information")

			if !*useCloudIdentityAPI {
				if g, ok := mocks[s]; ok {
					groups = g.Groups
				}
			} else {
				// yeah, i can de-dup this with the above...
				err = cisvc.Groups.Memberships.SearchTransitiveGroups("groups/-").Query(query).Pages(ctx, func(g *cloudidentity.SearchTransitiveGroupsResponse) error {
					for _, m := range g.Memberships {
						groups = append(groups, m.GroupKey.Id)
					}
					return nil
				})
				if err != nil {
					fmt.Printf("%v", err)
					http.Error(w, "Error happened in JSON marshal. Er", http.StatusInternalServerError)
				}
			}
			fmt.Printf("User [%s] --> %s\n", s, groups)

			gr.Groups = groups

			gg, err := json.Marshal(gr)
			if err != nil {
				fmt.Printf("%v", err)
				http.Error(w, "Error happened in JSON marshal. Er", http.StatusInternalServerError)
			}

			err = redisClient.Set(s, gg, cachInSeconds*time.Second).Err()
			if err != nil {
				fmt.Printf("redis Set error %v", err)
				http.Error(w, "Error saving value to redis", http.StatusInternalServerError)
			}

		} else if err != nil {
			fmt.Printf("Error reading from redis: %v\n", err)
			http.Error(w, "can't reading from redis", http.StatusInternalServerError)
		} else {
			err = json.Unmarshal([]byte(gg), gr)
			if err != nil {
				fmt.Printf("Error unmarshaling from redis: %v\n", err)
				http.Error(w, "can't reading from redis", http.StatusInternalServerError)
			}
			fmt.Println("Cached Groups ", gg)
		}
	}

	jsonResp, err := json.Marshal(gr)
	if err != nil {
		http.Error(w, "Error happened in JSON marshal. Error", http.StatusInternalServerError)
	}

	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", cachInSeconds)) // 30 days
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

func main() {
	flag.Parse()
	ctx := context.Background()

	if *useRedis {
		fmt.Printf("useRedis enabled\n")
		redisClient = redis.NewClient(&redis.Options{
			Addr: "redis.yourdomain.com:6379",
		})
		pong, err := redisClient.Ping().Result()
		if err != nil {
			fmt.Printf("Redis status Error%v", pong)
		}
		fmt.Printf("Redis: %v", pong)
	}

	fmt.Printf("%v\n", *useCloudIdentityAPI)
	if *useCloudIdentityAPI {
		fmt.Printf("useCloudIdentityAPI enabled\n")

		// if using a service account key (don't do this)
		// serviceAccountFile := "/path/to/svc_account.json"
		// serviceAccountJSON, err := ioutil.ReadFile(serviceAccountFile)
		// if err != nil {
		// 	fmt.Printf("Error Rading Service Account JSON File %v", err)
		// 	return
		// }

		// config, err := google.JWTConfigFromJSON(serviceAccountJSON, cloudidentity.CloudPlatformScope, cloudidentity.CloudIdentityGroupsReadonlyScope)
		// if err != nil {
		// 	fmt.Printf("Error Rading Service Account JSON File %v", err)
		// 	return
		// }
		// ts := config.TokenSource(ctx)

		// if the GCE/GKE's default service account has workspace permissions
		// ts, err := google.DefaultTokenSource(ctx)
		// if err != nil {
		// 	fmt.Printf("Error Rading Service Account JSON File %v", err)
		// 	return
		// }

		// using impersonation
		targetServiceAccount := "adminapi@fabled-ray-104117.iam.gserviceaccount.com"
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: targetServiceAccount,
			Scopes:          []string{cloudidentity.CloudPlatformScope, cloudidentity.CloudIdentityGroupsReadonlyScope},
		})
		if err != nil {
			fmt.Printf("Error Rading Service Account JSON File %v", err)
			return
		}

		cisvc, err = cloudidentity.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			fmt.Printf("Error creating Cloud Identity Service %v", err)
			return
		}

	}

	router := mux.NewRouter()
	router.Methods(http.MethodPost).Path("/authz").HandlerFunc(posthandler)
	server := &http.Server{
		Addr:    ":8443",
		Handler: router,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	//err := server.ListenAndServe()
	err := server.ListenAndServeTLS(*tlsCert, *tlsKey)
	fmt.Printf("Unable to start Server %v", err)

}
