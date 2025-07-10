using PingCastle.Data;
using PingCastle.Healthcheck;
using PingCastle.PingCastleLicense;
using PingCastle.Report;
using PingCastle.Rules;
using PingCastle.UserInterface;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace PingCastle.Bot
{


    public class Bot
    {
        private readonly IUserInterface _userIo = UserInterfaceFactory.GetUserInterface();

        public void Run(string pipeName)
        {
            BotInputOutput input;
            bool stop = false;

            XmlSerializer xs = new XmlSerializer(typeof(BotInputOutput));
            _userIo.DisplayMessage("Bot: hello");
            using (var pipe = BotStream.OpenPipeStream(pipeName))
            {
                while (!stop)
                {
                    try
                    {
                        var buffer = new byte[4];
                        int read = pipe.Read(buffer, 0, 4);
                        if (read < 4)
                            return;
                        int count = BitConverter.ToInt32(buffer, 0);
                        var data = new byte[count];
                        read = 0;
                        while (read < count)
                        {
                            int r = pipe.Read(data, read, count - read);
                            if (r == 0)
                            {
                                _userIo.DisplayMessage("Pipe shutdown");
                                return;
                            }
                            read += r;
                        }
                        _userIo.DisplayMessage("Bot: message received");
                        using (var ms = new MemoryStream(data))
                        {
                            input = (BotInputOutput)xs.Deserialize(ms);
                        }
                    }
                    catch (Exception ex)
                    {
                        _userIo.DisplayError("Exception when reading the input " + ex.Message);
                        _userIo.DisplayStackTrace("StackTrace:" + ex.StackTrace);
                        return;
                    }

                    BotInputOutput output;
                    string order = GetItem(input, "Command");
                    try
                    {
                        switch (order)
                        {
                            case "healthcheck":
                                output = RunHealthCheck(input);
                                break;
                            case "tohtml":
                                output = ToHtml(input);
                                break;
                            case "shutdown":
                                stop = true;
                                output = new BotInputOutput();
                                output.Data = new List<BotData>();
                                AddData(output, "Status", "shutdown");
                                break;
                            case null:
                                output = ExceptionOutput("Command not found");
                                break;
                            default:
                                output = ExceptionOutput("Invalid command " + order);
                                break;
                        }
                    }
                    catch (Exception ex)
                    {
                        output = ExceptionOutput("Exception during the job " + ex.Message, ex.StackTrace);
                        _userIo.DisplayMessage("Exception:" + ex.Message);
                        _userIo.DisplayStackTrace("StackTrace:" + ex.StackTrace);
                    }

                    _userIo.DisplayMessage("Writing data");

                    using (var ms = new MemoryStream())
                    using (XmlWriter writer = XmlWriter.Create(ms))
                    {
                        xs.Serialize(writer, output);
                        ms.Position = 0;
                        var buffer = ms.GetBuffer();
                        var t = BitConverter.GetBytes((int)ms.Length);
                        pipe.Write(t, 0, 4);
                        pipe.Write(buffer, 0, (int)ms.Length);
                        _userIo.DisplayMessage("Bot: message sent");
                    }
                }
            }
            _userIo.DisplayMessage("Exiting");
        }

        private string GetItem(BotInputOutput input, string key)
        {
            foreach (var k in input.Data)
            {
                if (k.Key == key)
                    return k.Value;
            }
            return null;
        }

        private BotInputOutput ExceptionOutput(string message, string stacktrace = null)
        {
            var o = new BotInputOutput();
            o.Data = new List<BotData>();
            AddData(o, "Status", "Error");
            AddData(o, "Error", message);
            if (!string.IsNullOrEmpty(stacktrace))
            {
                AddData(o, "StackTrace", stacktrace);
            }
            return o;
        }

        private BotInputOutput RunHealthCheck(BotInputOutput input)
        {
            try
            {
                var analyze = new HealthcheckAnalyzer();
                var parameters = new PingCastleAnalyzerParameters();
                parameters.Server = GetItem(input, "Server");
                var login = GetItem(input, "Login");
                var password = GetItem(input, "Password");
                if (!string.IsNullOrEmpty(login) && !string.IsNullOrEmpty(password))
                    parameters.Credential = new System.Net.NetworkCredential(login, password);
                var port = GetItem(input, "Port");
                if (!string.IsNullOrEmpty(port))
                    parameters.Port = int.Parse(port);
                var healthcheck = analyze.PerformAnalyze(parameters);

                var o = new BotInputOutput();
                o.Data = new List<BotData>();
                AddData(o, "Status", "OK");
                AddData(o, "Target", parameters.Server);

                int riskId = 0;
                foreach (var risk in healthcheck.RiskRules)
                {
                    riskId++;
                    var rule = RuleSet<HealthcheckData>.GetRuleFromID(risk.RiskId);
                    AddData(o, "Rationale_" + riskId, risk.Rationale);
                    AddData(o, "Title_" + riskId, rule.Title);
                    AddData(o, "Solution_" + riskId, rule.Solution);
                    AddData(o, "Points_" + riskId, risk.Points.ToString());
                    AddData(o, "Documentation_" + riskId, rule.Documentation);
                    AddData(o, "TechnicalExplanation_" + riskId, rule.TechnicalExplanation);
                    foreach (var d in rule.Details)
                    {
                        AddData(o, "Detail_" + riskId, d);
                    }
                }

                healthcheck.SetExportLevel(PingCastleReportDataExportLevel.Full);
                var xmlreport = DataHelper<HealthcheckData>.SaveAsXml(healthcheck, null, false);
                AddData(o, "Report", xmlreport);

                return o;
            }
            catch (Exception ex)
            {
                _userIo.DisplayError("Exception:" + ex.Message);
                _userIo.DisplayStackTrace("StackTrace:" + ex.StackTrace);
                return ExceptionOutput("Exception during the healthcheck " + ex.Message, ex.StackTrace);
            }
        }

        private BotInputOutput ToHtml(BotInputOutput input)
        {
            try
            {
                var xml = GetItem(input, "Report");
                using (var ms = new MemoryStream(UnicodeEncoding.UTF8.GetBytes(xml)))
                {
                    HealthcheckData healthcheckData = DataHelper<HealthcheckData>.LoadXml(ms, "bot", null);
                    var license = LicenseCache.Instance.GetLicense();
                    var endUserReportGenerator = new ReportHealthCheckSingle(license);
                    var report = endUserReportGenerator.GenerateReportFile(healthcheckData, healthcheckData.GetHumanReadableFileName());

                    var o = new BotInputOutput();
                    o.Data = new List<BotData>();
                    AddData(o, "Status", "OK");
                    AddData(o, "Report", report);
                    return o;
                }
            }
            catch (Exception ex)
            {
                _userIo.DisplayError("Exception:" + ex.Message);
                _userIo.DisplayStackTrace("StackTrace:" + ex.StackTrace);
                return ExceptionOutput("Exception during the job " + ex.Message, ex.StackTrace);
            }
        }

        private static void AddData(BotInputOutput o, string key, string value)
        {
            o.Data.Add(new BotData(key, value));
        }
    }
}
