// MIT License
//
// # Copyright (c) 2024 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package krb5ssp

import (
	"os"
	"strings"

	"github.com/jfjallid/gokrb5/v8/client"
	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/credentials"
)

func getClientFromCachedTicket(cfg *config.Config, username, domain, spn string, spnAliases map[string][]string, settings ...func(*client.Settings)) (c *client.Client, fallbackSPN string, err error) {
	cacheFile := os.Getenv("KRB5CCNAME")
	if cacheFile != "" {
		var cache *credentials.CCache
		//Check if a file
		fileinfo, err2 := os.Stat(cacheFile)
		err = err2
		if err != nil {
			log.Errorln(err)
			return
		}
		log.Debugf("Found ccache file: %s\n", cacheFile)
		mode := fileinfo.Mode()
		if mode.IsRegular() {
			// Try loading TGT and TGS from ccache
			cache, err = credentials.LoadCCache(cacheFile)
			if err != nil {
				log.Errorln(err)
				return
			}
			cacheDomain := cache.GetClientRealm()
			// Might be that ccache domain is fqdn but user provides netbios domain name.
			netbiosDomain := strings.Split(cacheDomain, ".")[0]
			if domain != "" && (!strings.EqualFold(cacheDomain, domain) && !strings.EqualFold(netbiosDomain, domain)) {
				log.Infof("Kerberos cache only contains credentials for the %s domain, but not for %s as requested\n", cacheDomain, domain)
				return
			}
			cacheUser := cache.DefaultPrincipal.PrincipalName.PrincipalNameString()
			if username != "" && !strings.EqualFold(username, cacheUser) {
				log.Infof("Kerberos cache only contains credentials for the %s username, but not for %s as requested\n", cacheUser, username)
				return
			}
			spnParts := strings.Split(spn, "/")
			// Build ordered candidate list: primary SPN first, then configured aliases.
			targets := [][]string{spnParts}
			if len(spnParts) >= 2 {
				aliases := spnAliases
				if aliases == nil {
					aliases = defaultSPNAliases
				}
				service := strings.ToLower(spnParts[0])
				// Construct alternative SPNs to look for in the ccache
				for _, altService := range aliases[service] {
					altParts := append([]string{altService}, spnParts[1:]...)
					targets = append(targets, altParts)
				}
			}
			var matched []string
			c, matched, err = client.NewFromCCacheWithFallbacks(cache, targets, cfg, settings...)
			if matched != nil && !strings.EqualFold(matched[0], spnParts[0]) {
				fallbackSPN = strings.Join(matched, "/")
				log.Debugf("Requested SPN %q not cached; using %q instead", spn, fallbackSPN)
			}
			if c == nil {
				if err != nil {
					log.Errorf("error looking for cached ticket for SPN %q: %s", spn, err)
				}
				return
			}
			log.Debugln("Created client from ccache")
		} else if mode.IsDir() {
			log.Errorln("KRB5CCNAME points to a directory and not a file which is not supported")
			return
		}
		// Check if we created a client or not.
		if c == nil {
			log.Infoln("Found no useable Kerberos credentials in the cache")
			return
		}

		log.Infoln("Using Kerberos cached credentials")
		err = nil
	} else {
		log.Debugln("No cache specified in KRB5CCNAME")
	}

	return
}
