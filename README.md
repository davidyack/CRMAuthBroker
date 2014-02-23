CRMAuthBroker
=============

Helper for connecting from Windows Phone to Microsoft Dynamics CRM 

Designed to make it as simple as possible for connecting to CRM - the following is an example using the library - the only requirement for the page is to provide a hidden WebBrowser control 

    CRMAuthenticationBroker broker = new CRMAuthenticationBroker(app.ClientID, app.DomainName, app.RedirectUri);
   
    var token = await broker.AcquireToken(authBrowser);
 
Once you have the token, you can proceed to use either the OData or Soap endpoints to interact with CRM


A detailed walkthrough can be watched via the @XRMVirtual recorded live meeting here https://www311.livemeeting.com/cc/usergroups/view?id=3JGDNF


More training on Microsoft Dynamics CRM can be found here http://pluralsight.com/training/Authors/Details/david-yack 
