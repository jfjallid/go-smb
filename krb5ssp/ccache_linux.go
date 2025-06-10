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

func getClientFromCachedTicket(cfg *config.Config, username, domain, spn string, settings ...func(*client.Settings)) (c *client.Client, err error) {
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
		mode := fileinfo.Mode()
		if mode.IsRegular() {
			// Try loading TGT and TGS from ccache
			cache, err = credentials.LoadCCache(cacheFile)
			if err != nil {
				log.Errorln(err)
				return
			}
			cacheDomain := cache.GetClientRealm()
			if domain != "" && !strings.EqualFold(cacheDomain, domain) {
				log.Infof("Kerberos cache only contains credentials for the %s domain, but not for %s as requested\n", cacheDomain, domain)
				return
			}
			cacheUser := cache.DefaultPrincipal.PrincipalName.PrincipalNameString()
			if username != "" && !strings.EqualFold(username, cacheUser) {
				log.Infof("Kerberos cache only contains credentials for the %s username, but not for %s as requested\n", cacheUser, username)
				return
			}
			c, err = client.NewFromCCache(cache, strings.Split(spn, "/"), cfg, settings...)
			if err != nil {
				log.Errorln(err)
				return
			}
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
