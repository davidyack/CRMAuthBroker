using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ctccrm.OAuthBroker
{
    /// <summary>
    /// Store context information used by CRM Authentication Broker
    /// </summary>
    internal class CRMAuthenticationContext
    {
        public string RedirectUri { get; set; }
        public string Domain { get; set; }
        public string ClientID { get; set; }
        public string Code { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime Expires { get; set; }

        public bool IsAccessTokenExpired()
        {
            if (string.IsNullOrEmpty(this.AccessToken))
                return true;

            if (Expires < DateTime.Now)
                return true;

            return false;
        }

        public bool IsRefreshViable()
        {
            if ((!string.IsNullOrEmpty(this.RefreshToken)) && (this.Expires < DateTime.Now))
            {
                return true;
            }

            return false;
        }

    }
}
