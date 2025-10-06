using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Security.Principal;
using System.Text;

namespace PingCastle.Exports
{
    public class ExportChanges : ExportBase
    {
        private readonly IUserInterface _ui = UserInterfaceFactory.GetUserInterface();

        public override string Name
        {
            get { return "changes"; }
        }

        public override string Description
        {
            get { return "Export all modifications that occurs in the domain in real time"; }
        }

        public override void Export(string filename)
        {
            using (LdapConnection connect = new LdapConnection(new LdapDirectoryIdentifier(Settings.Server, Settings.Port == 0 ? 389 : Settings.Port), Settings.Credential))
            {
                var filter = "(&(objectClass=*))";
                var searchRequest = new SearchRequest(null, filter, SearchScope.Base);
                var response = connect.SendRequest(searchRequest) as SearchResponse;
                string root = (string)response.Entries[0].Attributes["defaultNamingContext"][0];
                connect.Bind();

                using (StreamWriter sw = File.CreateText(filename))
                {
                    var header = new List<string>();
                    header.Add("Date");
                    header.Add("DistinguishedName");
                    header.Add("Attribute");
                    header.Add("Value");

                    sw.WriteLine(string.Join("\t", header.ToArray()));


                    EventHandler<ObjectChangedEventArgs> callback =
                        (object sender, ObjectChangedEventArgs e) =>
                        {
                            DisplayAdvancementWarning(e.Result.DistinguishedName);
                            foreach (string attributeName in e.Result.Attributes.AttributeNames)
                            {
                                foreach (byte[] item in e.Result.Attributes[attributeName].GetValues(typeof(byte[])))
                                {
                                    string i;
                                    // there is no easy way to know the synthax of the object
                                    // see https://social.technet.microsoft.com/wiki/contents/articles/52570.active-directory-syntaxes-of-attributes.aspx
                                    
                                    // so we try each well known type one by one
                                    try
                                    {
                                        i = new SecurityIdentifier(item, 0).Value;
                                    }
                                    catch
                                    {
                                        try
                                        {
                                            i = new Guid(item).ToString();
                                        }
                                        catch
                                        {
                                            try
                                            {
                                                i = Encoding.UTF8.GetString(item);
                                                for (int j = 0; j < i.Length; j++)
                                                {
                                                    var ch = i[j];
                                                    var ich = (int)ch;
                                                    if (ich > 127 || ich < 31) // not ascii or extended ascii
                                                    {
                                                        i = BitConverter.ToString(item);
                                                        break;
                                                    }
                                                }
                                            }
                                            catch
                                            {
                                                i = BitConverter.ToString(item);
                                            }
                                        }
                                    }

                                    var data = new List<string>();
                                    data.Add(DateTime.Now.ToString("u"));
                                    data.Add(e.Result.DistinguishedName);
                                    data.Add(attributeName);
                                    data.Add(i);
                                    sw.WriteLine(string.Join("\t", data.ToArray()));
                                    sw.Flush();
                                }
                            }
                        };


                    using (ChangeNotifier notifier = new ChangeNotifier(connect))
                    {

                        //register some objects for notifications (limit 5)
                        notifier.Register(root, SearchScope.Subtree);

                        notifier.ObjectChanged += callback;

                        DisplayAdvancement("Waiting for changes...");
                        DisplayAdvancement("Press ENTER to stop monitoring the changes");
                        _ui.AskForString();
                    }
                }

                DisplayAdvancement("Done");
            }
        }

        private static void DisplayAdvancementWarning(string data)
        {
            string value = "[" + DateTime.Now.ToLongTimeString() + "] " + data;
            UserInterfaceFactory.GetUserInterface().DisplayWarning(value);
            Trace.WriteLine(value);
        }


        public class ChangeNotifier : IDisposable
        {
            LdapConnection _connection;
            List<IAsyncResult> _results = new List<IAsyncResult>();

            public ChangeNotifier(LdapConnection connection)
            {
                _connection = connection;
                _connection.AutoBind = true;
            }

            public void Register(string dn, SearchScope scope)
            {
                SearchRequest request = new SearchRequest(dn, "(objectClass=*)", scope, null);

                request.Controls.Add(new DirectoryNotificationControl());

                IAsyncResult result = _connection.BeginSendRequest(
                    request,
                    TimeSpan.FromDays(1), //set timeout to a day...
                    PartialResultProcessing.ReturnPartialResultsAndNotifyCallback,
                    Notify,
                    request
                    );

                _results.Add(result);
            }

            private void Notify(IAsyncResult result)
            {
                PartialResultsCollection prc = _connection.GetPartialResults(result);

                foreach (SearchResultEntry entry in prc)
                {
                    OnObjectChanged(new ObjectChangedEventArgs(entry));
                }
            }

            private void OnObjectChanged(ObjectChangedEventArgs args)
            {
                if (ObjectChanged != null)
                {
                    ObjectChanged(this, args);
                }
            }

            public event EventHandler<ObjectChangedEventArgs> ObjectChanged;

            #region IDisposable Members

            public void Dispose()
            {
                foreach (var result in _results)
                {
                    _connection.Abort(result);
                }
            }

            #endregion
        }

        public class ObjectChangedEventArgs : EventArgs
        {
            public ObjectChangedEventArgs(SearchResultEntry entry)
            {
                Result = entry;
            }

            public SearchResultEntry Result { get; set; }

        }
    }
}

