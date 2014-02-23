using Microsoft.Phone.Controls;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.IO.IsolatedStorage;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ctccrm.OAuthBroker
{
    /// <summary>
    /// Helper class to authenticate users to CRM via Windows Azure Active Directory
    /// </summary>
    public class CRMAuthenticationBroker
    {
        //instance of browser from current UI
        WebBrowser _Browser = null;

        //Track status of async authentication work
        TaskCompletionSource<string> _TCS = null;

        //Context information for current session
        CRMAuthenticationContext _AuthContext = new CRMAuthenticationContext();

        /// <summary>
        /// Allow callers to override persistance of tokens
        /// </summary>
        public bool DontPersist { get; set; }

        /// <summary>
        /// Intialize new instance of Auth Broker with client ID, domain and redirect that was registered
        /// </summary>
        /// <param name="clientID"></param>
        /// <param name="domain"></param>
        /// <param name="redirectUri"></param>
        public CRMAuthenticationBroker(string clientID, string domain, string redirectUri)
        {
            //if we have persisted the tokens reload
            if (SaveAuthContextExists())
                LoadAuthContext();

            //save off the client info in context
            _AuthContext.RedirectUri = redirectUri;
            _AuthContext.Domain = domain;
            _AuthContext.ClientID = clientID;
        }

        /// <summary>
        /// Worker method to acquire, refresh a token
        /// this method will show a browser as needed to 
        /// complete the authentication flow
        /// </summary>
        /// <param name="browser"></param>
        /// <returns></returns>
        public Task<string> AcquireToken(WebBrowser browser)
        {

            _Browser = browser;

            _TCS = new TaskCompletionSource<string>();

            //Check if existing token has expired, if so try refresh
            if (_AuthContext.IsAccessTokenExpired())
            {
                //If expired and we have a refresh token, try that 
                if (_AuthContext.IsRefreshViable())
                {
                    GetRefreshToken();
                }
                else
                {
                    //Start the flow from the top with the user providing credentials
                    NavigateBrowserToAuthScreen();
                }
            }
            else
            {
                _TCS.SetResult(_AuthContext.AccessToken);
            }
            return _TCS.Task;
        }

        /// <summary>
        /// Helper method to navigate browser to CRM auth page
        /// </summary>
        private void NavigateBrowserToAuthScreen()
        {
            _Browser.Navigating += browser_Navigating;
            _Browser.IsScriptEnabled = true;
            _Browser.Dispatcher.BeginInvoke(() =>
            {
                _Browser.Visibility = System.Windows.Visibility.Visible;
            });

            string authURL = string.Format(
                "https://login.windows.net/{0}/oauth2/authorize?response_type=code&resource={1}&client_id={2}&redirect_uri={3}",
                _AuthContext.Domain, "Microsoft.CRM", _AuthContext.ClientID, _AuthContext.RedirectUri);

            //navigate to it
            _Browser.Navigate(new Uri(authURL));
        }

        /// <summary>
        /// Handler method to handle navigating and check url to match Return URL
        /// Matching Return URL indicates completion of that part of auth Flow
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        void browser_Navigating(object sender, NavigatingEventArgs e)
        {
            string returnURL = e.Uri.ToString();

            if (returnURL.StartsWith(_AuthContext.RedirectUri))
            {
                _AuthContext.Code = e.Uri.Query.Remove(0, 6);
                e.Cancel = true;
                _Browser.Visibility = System.Windows.Visibility.Collapsed;
                GetToken();
            }
        }

        /// <summary>
        /// Build request for getting an Access Token
        /// </summary>
        private void GetToken()
        {
            HttpWebRequest hwr =
                WebRequest.Create(
                    string.Format("https://login.windows.net/{0}/oauth2/token",
                                   _AuthContext.Domain)) as HttpWebRequest;
            hwr.Method = "POST";
            hwr.ContentType = "application/x-www-form-urlencoded";
            hwr.BeginGetRequestStream(new AsyncCallback(SendTokenEndpointRequest), hwr);
        }
      
        /// <summary>
        /// Build the post data for getting an Access Token
        /// </summary>
        /// <param name="rez"></param>
        private void SendTokenEndpointRequest(IAsyncResult rez)
        {
            HttpWebRequest hwr = rez.AsyncState as HttpWebRequest;
            byte[] bodyBits = Encoding.UTF8.GetBytes(
                string.Format(
                    "grant_type=authorization_code&code={0}&client_id={1}&redirect_uri={2}",
                    _AuthContext.Code,
                    _AuthContext.ClientID,
                    HttpUtility.UrlEncode(_AuthContext.RedirectUri)));
            Stream st = hwr.EndGetRequestStream(rez);
            st.Write(bodyBits, 0, bodyBits.Length);
            st.Close();
            hwr.BeginGetResponse(new AsyncCallback(RetrieveTokenEndpointResponse), hwr);
        }

        /// <summary>
        /// Handle the response from requesting Access Token
        /// If Persist is enabled store in protected storage for the app
        /// </summary>
        /// <param name="rez"></param>
        private void RetrieveTokenEndpointResponse(IAsyncResult rez)
        {
            HttpWebRequest hwr = rez.AsyncState as HttpWebRequest;
            HttpWebResponse resp = hwr.EndGetResponse(rez) as HttpWebResponse;

            StreamReader sr = new StreamReader(resp.GetResponseStream());
            string responseString = sr.ReadToEnd();
            JObject jo = JsonConvert.DeserializeObject(responseString) as JObject;
            _AuthContext.AccessToken = (string)jo["access_token"];
            _AuthContext.RefreshToken = (string)jo["refresh_token"];
            _AuthContext.Expires = DateTime.Now.AddSeconds((int)jo["expires_in"]);

            //Unregister event handler and hide the browser
            _Browser.Navigating -= browser_Navigating;
            _Browser.Dispatcher.BeginInvoke(() =>
            {
                _Browser.Visibility = System.Windows.Visibility.Collapsed;
            });

            //If persist has not been disabled encrypt and store the token data
            if (!DontPersist)
                StoreAuthContext();

            _TCS.SetResult(_AuthContext.AccessToken);

        }

        /// <summary>
        /// Build the request to get a new Access Token using the  Refresh Token
        /// </summary>
        private void GetRefreshToken()
        {
            HttpWebRequest hwr =
                WebRequest.Create(
                    string.Format("https://login.windows.net/{0}/oauth2/token",
                                   _AuthContext.Domain)) as HttpWebRequest;
            hwr.Method = "POST";
            hwr.ContentType = "application/x-www-form-urlencoded";
            hwr.BeginGetRequestStream(new AsyncCallback(SendRefreshTokenEndpointRequest), hwr);
        }
              
        /// <summary>
        /// Build the post data to get use the refresh token to get an access token
        /// </summary>
        /// <param name="rez"></param>
        private void SendRefreshTokenEndpointRequest(IAsyncResult rez)
        {
            HttpWebRequest hwr = rez.AsyncState as HttpWebRequest;
            byte[] bodyBits = Encoding.UTF8.GetBytes(
                string.Format(
                    "grant_type=refresh_token&refresh_token={0}&client_id={1}&resource={2}",
                    _AuthContext.RefreshToken,
                    _AuthContext.ClientID, "Microsoft.CRM", _AuthContext.Code));
            Stream st = hwr.EndGetRequestStream(rez);
            st.Write(bodyBits, 0, bodyBits.Length);
            st.Close();

            hwr.BeginGetResponse(new AsyncCallback(RetrieveRefreshTokenEndpointResponse), hwr);
        }
        /// <summary>
        /// Handle the response from getting a access token using the refresh token
        /// </summary>
        /// <param name="rez"></param>
        private void RetrieveRefreshTokenEndpointResponse(IAsyncResult rez)
        {
            HttpWebRequest hwr = rez.AsyncState as HttpWebRequest;
            HttpWebResponse resp = hwr.EndGetResponse(rez) as HttpWebResponse;

            StreamReader sr = new StreamReader(resp.GetResponseStream());
            string responseString = sr.ReadToEnd();
            JObject jo = JsonConvert.DeserializeObject(responseString) as JObject;
            _AuthContext.AccessToken = (string)jo["access_token"];
            _AuthContext.RefreshToken = (string)jo["refresh_token"];
            _AuthContext.Expires = DateTime.Now.AddSeconds((int)jo["expires_in"]);


            _Browser.Navigating -= browser_Navigating;
            _Browser.Dispatcher.BeginInvoke(() =>
            {
                _Browser.Visibility = System.Windows.Visibility.Collapsed;
            });

            if (!DontPersist)
                StoreAuthContext();

            _TCS.SetResult(_AuthContext.AccessToken);

        }

        /// <summary>
        /// Helper method to store the context in encrypted isolated storage
        /// </summary>
        private void StoreAuthContext()
        {

            var authContextString = JsonConvert.SerializeObject(_AuthContext);

            IsolatedStorageFile file = IsolatedStorageFile.GetUserStoreForApplication();
            IsolatedStorageFileStream writestream = new IsolatedStorageFileStream("AuthFile", System.IO.FileMode.Create, System.IO.FileAccess.Write, file);

            byte[] PinByte = Encoding.UTF8.GetBytes(authContextString);

            // Encrypt the PIN by using the Protect() method.
            byte[] ProtectedPinByte = ProtectedData.Protect(PinByte, null);


            // Write pinData to the file.
            Stream writer = new StreamWriter(writestream).BaseStream;
            writer.Write(ProtectedPinByte, 0, ProtectedPinByte.Length);
            writer.Close();
            writestream.Close();

        }
        /// <summary>
        /// helper method to load the context from encrypted isolated storage
        /// </summary>
        private void LoadAuthContext()
        {
            IsolatedStorageFile file = IsolatedStorageFile.GetUserStoreForApplication();
            IsolatedStorageFileStream readstream = new IsolatedStorageFileStream("AuthFile", System.IO.FileMode.Open, FileAccess.Read, file);

            // Read the PIN from the file.
            Stream reader = new StreamReader(readstream).BaseStream;
            byte[] pinArray = new byte[reader.Length];

            reader.Read(pinArray, 0, pinArray.Length);
            reader.Close();
            readstream.Close();

            // Decrypt the PIN by using the Unprotect method.
            byte[] PinByte = ProtectedData.Unprotect(pinArray, null);

            // Convert the PIN from byte to string and display it in the text box.
            var objData = Encoding.UTF8.GetString(PinByte, 0, PinByte.Length);

            _AuthContext = JsonConvert.DeserializeObject<CRMAuthenticationContext>(objData);


        }
        /// <summary>
        /// Helper method to check if saved context exists
        /// </summary>
        /// <returns></returns>
        private bool SaveAuthContextExists()
        {
            IsolatedStorageFile file = IsolatedStorageFile.GetUserStoreForApplication();
            return file.FileExists("AuthFile");
        }
        /// <summary>
        /// Clear previously saved authentication context
        /// Call this in your Sign out flow
        /// </summary>
        public void ClearSavedAuthentication()
        {
            if (SaveAuthContextExists())
            {
                IsolatedStorageFile file = IsolatedStorageFile.GetUserStoreForApplication();
                file.DeleteFile("AuthFile");
                _AuthContext = new CRMAuthenticationContext();
            }
        }
    }
}
