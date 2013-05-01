using System;
using System.IO;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.FileSystems;
using Microsoft.Owin.Hosting;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Forms;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.StaticFiles;
using Owin;

namespace KatanaFormsAuthn
{
    class Program
    {
        static void Main()
        {
            WebApp.Start<WebAppStartup>(8350);
            Console.WriteLine("Started webapp on port 8350.  Hit enter to exit.");
            Console.ReadLine();
        }
    }

    public class WebAppStartup
    {
        public void Configuration(IAppBuilder builder)
        {
            var rootDirectory = Environment.CurrentDirectory;
            var loginDirectory = Path.Combine(rootDirectory, "login");

            var fs = new PhysicalFileSystem(rootDirectory);
            var loginFs = new PhysicalFileSystem(loginDirectory);

            var dfo = new DefaultFilesOptions();
            dfo.DefaultFileNames.Add("index.html");
            dfo.FileSystem = fs;

            var sfo = new StaticFileOptions
                      {
                          FileSystem = fs
                      };
            var loginSfo = new StaticFileOptions
                           {
                               FileSystem = loginFs
                           };

            builder.SetDataProtectionProvider(new DpapiDataProtectionProvider());
            var formsAuthenticationProvider = new FormsAuthenticationProvider();


            formsAuthenticationProvider.OnValidateLogin = context =>
            {
                Console.WriteLine("Validating Login");
                Console.WriteLine("================");
                Console.WriteLine("  Context.AuthType: " + context.AuthenticationType);
                Console.WriteLine("  Context.Identity: " + (context.Identity != null ? context.Identity.Name : "Not set"));
                Console.WriteLine("  Context.Environment:");

                var response = new OwinResponse(context.Environment);

                if (LoginContext.GetIsLoginRequest(context.Environment))
                {
                    // Need to retrieve username and password from environment b/c it doesn't
                    // come through in the context (even though the context constructor accepts them)

                    var username = context.Environment["formsauthn.username"].ToString();
                    var password = context.Environment["formsauthn.password"].ToString();
                    var remember = bool.Parse(context.Environment["formsauthn.remember"].ToString());

                    Console.WriteLine("  Request.Username: " + username);
                    Console.WriteLine("  Request.Password: " + password);
                    Console.WriteLine("  Request.Remember: " + remember);

                    if (username == password)
                    {
                        var identity = new ClaimsIdentity(
                            new GenericIdentity(username, context.AuthenticationType),
                            new[]
                            {
                                new Claim(ClaimTypes.IsPersistent, remember.ToString())
                            }
                            );

                        // I assumed that this would take care of populating the cookie for me... but not so much.
                        context.Signin(identity);

                        var msg = "Access granted.";
                        Console.WriteLine(msg);
                        var msgBytes = Encoding.UTF8.GetBytes(msg);
                        return response.Body.WriteAsync(msgBytes, 0, msgBytes.Length);
                    }
                    else
                    {
                        var msg = "Access denied.  Try with username=password";
                        Console.WriteLine(msg);
                        var msgBytes = Encoding.UTF8.GetBytes(msg);
                        return response.Body.WriteAsync(msgBytes, 0, msgBytes.Length);
                    }
                }
                else
                {
                    foreach (var item in context.Environment)
                    {
                        Console.WriteLine("  {0}={1}",
                                          item.Key,
                                          item.Value != null
                                              ? (item.Value is string ? (string) item.Value : item.Value.GetType().FullName)
                                              : "Not set"
                            );
                    }
                }

                return response.Body.WriteAsync(new byte[] { }, 0, 0);
            };
        

            builder.UseFormsAuthentication(
                new FormsAuthenticationOptions
                {                                    
                    CookieHttpOnly = true,
                    CookieName = "AuthCookie",
                    CookiePath = "/",
                    CookieSecure = false,
                    LoginPath = "/login/",
                    ExpireTimeSpan = TimeSpan.FromHours(1),
                    ReturnUrlParameter = "returnUrl",
                    SlidingExpiration = true,
                    Provider = formsAuthenticationProvider
                }
            );
            builder.UseApplicationSignInCookie();
            builder.UseDefaultFiles(dfo);
            builder.UseErrorPage();
            builder.MapPath("/login", loginBuilder => loginBuilder.UseProcessLoginPostback(formsAuthenticationProvider).UseStaticFiles(loginSfo));
            builder.UseDenyAnonymous().UseStaticFiles(sfo);
        }
    }
}