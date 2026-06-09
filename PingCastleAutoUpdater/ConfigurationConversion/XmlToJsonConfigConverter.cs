namespace PingCastleAutoUpdater.ConfigurationConversion
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text.Json;
    using System.Text.Json.Nodes;
    using System.Xml;

    /// <summary>
    /// Converts XML application configuration (PingCastle.exe.config) to JSON format (appsettings.console.json).
    /// Handles custom configuration sections and standard .NET configuration elements.
    /// Includes comprehensive reporting and unmapped settings preservation.
    /// </summary>
    public class XmlToJsonConfigConverter : IConfigConverter
    {
        private ConversionReport _report;

        /// <summary>
        /// Gets the last conversion report
        /// </summary>
        public ConversionReport LastReport => _report;

        /// <summary>
        /// Converts XML configuration file to JSON format, mapping all configuration sections.
        /// </summary>
        /// <param name="xmlConfigPath">Path to the XML configuration file</param>
        /// <param name="jsonConfigPath">Path where the JSON configuration file should be saved</param>
        /// <param name="deleteSourceOnCompletion">Whether to delete the source file on completion of the conversion.</param>
        /// <param name="createBackup">Whether to create a backup of the XML file. Only create backups for original user configs, not temp files or dry-run files</param>
        public void ConvertXmlConfigToJson(string xmlConfigPath, string jsonConfigPath, bool deleteSourceOnCompletion = true, bool createBackup = false)
        {
            _report = new ConversionReport
            {
                SourcePath = xmlConfigPath,
                TargetPath = jsonConfigPath
            };

            string backupPath = xmlConfigPath + ".bak";

            try
            {
                // Step 1: Create backup before conversion only if requested and source file exists
                if (createBackup && System.IO.File.Exists(xmlConfigPath))
                {
                    try
                    {
                        System.IO.File.Copy(xmlConfigPath, backupPath, overwrite: true);
                        _report.BackupCreated = true;
                        _report.BackupPath = backupPath;
                    }
                    catch (Exception ex)
                    {
                        _report.Warnings.Add($"Warning: Could not create backup of XML file: {ex.Message}");
                    }
                }

                // Diagnostic logging for path resolution issues
                string fullXmlPath = System.IO.Path.GetFullPath(xmlConfigPath);
                if (!System.IO.File.Exists(fullXmlPath))
                {
                    Console.WriteLine($"[DEBUG] Attempting to read XML configuration from: {fullXmlPath}");
                    Console.WriteLine($"[DEBUG] File exists: False");

                    // List files in the directory to help diagnose
                    string directory = System.IO.Path.GetDirectoryName(fullXmlPath);
                    if (System.IO.Directory.Exists(directory))
                    {
                        var files = System.IO.Directory.GetFiles(directory, "*.config");
                        if (files.Length > 0)
                        {
                            Console.WriteLine($"[DEBUG] Found .config files in directory:");
                            foreach (var file in files)
                            {
                                Console.WriteLine($"[DEBUG]   - {System.IO.Path.GetFileName(file)}");
                            }
                        }
                    }
                }

                var xmlDoc = new XmlDocument();
                xmlDoc.Load(xmlConfigPath);
                var root = xmlDoc.DocumentElement;
                if (root == null)
                {
                    throw new ConfigConversionException("Invalid XML configuration document structure");
                }

                var jsonObject = new JsonObject();

                // Convert License section
                var licenseSection = root.SelectSingleNode("LicenseSettings") as XmlElement;
                if (licenseSection != null)
                {
                    jsonObject["License"] = ConvertLicenseSettings(licenseSection);
                    _report.SectionsConverted.Add("License");
                    _report.TotalSettingsMapped++;
                }

                // Convert Encryption section
                var encryptionSection = root.SelectSingleNode("encryptionSettings") as XmlElement;
                if (encryptionSection != null)
                {
                    jsonObject["Encryption"] = ConvertEncryptionSettings(encryptionSection);
                    _report.SectionsConverted.Add("Encryption");
                    _report.TotalSettingsMapped++;
                }

                // Convert HoneyPot section
                var honeyPotSection = root.SelectSingleNode("honeyPotSettings") as XmlElement;
                if (honeyPotSection != null)
                {
                    jsonObject["HoneyPot"] = ConvertHoneyPotSettings(honeyPotSection);
                    _report.SectionsConverted.Add("HoneyPot");
                    _report.TotalSettingsMapped++;
                }

                // Convert Infrastructure section
                var infrastructureSection = root.SelectSingleNode("infrastructureSettings") as XmlElement;
                if (infrastructureSection != null)
                {
                    jsonObject["Infrastructure"] = ConvertInfrastructureSettings(infrastructureSection);
                    _report.SectionsConverted.Add("Infrastructure");
                    _report.TotalSettingsMapped++;
                }

                // Convert CustomRules section
                var customRulesSection = root.SelectSingleNode("customRulesSettings") as XmlElement;
                if (customRulesSection != null)
                {
                    jsonObject["CustomRules"] = ConvertCustomRulesSettings(customRulesSection);
                    _report.SectionsConverted.Add("CustomRules");
                    _report.TotalSettingsMapped++;
                }

                // Convert Brand settings from appSettings
                var appSettings = root.SelectSingleNode("appSettings") as XmlElement;
                if (appSettings != null)
                {
                    jsonObject["Brand"] = ConvertBrandSettings(appSettings);
                    _report.SectionsConverted.Add("Brand");
                    _report.TotalSettingsMapped++;
                }

                // Convert SMTP settings from system.net
                var systemNet = root.SelectSingleNode("system.net") as XmlElement;
                if (systemNet != null)
                {
                    var smtpSettings = ConvertSmtpSettings(systemNet);
                    if (smtpSettings != null)
                    {
                        jsonObject["Smtp"] = smtpSettings;
                        _report.SectionsConverted.Add("SMTP");
                        _report.TotalSettingsMapped++;
                    }
                }

                // Detect unmapped custom sections
                DetectUnmappedCustomSections(root, jsonObject);

                // Add example brand section
                jsonObject["_Brand_Example_Comment"] = "For brand customization for customers having a license, uncomment and modify the Brand section above with the values below:";
                var brandExample = new JsonObject
                {
                    ["_BrandLogo"] = "base64 encoded icon",
                    ["_BrandCss"] = ".pingcastle-css {color: red;}",
                    ["_BrandJs"] = "alert('test')"
                };
                jsonObject["_Brand_Example"] = brandExample;

                // Step 2: Save JSON to file
                var options = new JsonSerializerOptions { WriteIndented = true };
                string jsonContent = jsonObject.ToJsonString(options);
                System.IO.File.WriteAllText(jsonConfigPath, jsonContent);

                // Step 3: Conversion successful - optionally delete original XML
                if (deleteSourceOnCompletion && System.IO.File.Exists(xmlConfigPath) && System.IO.File.Exists(jsonConfigPath))
                {
                    try
                    {
                        System.IO.File.Delete(xmlConfigPath);
                        _report.XmlRenamedToBackup = true;
                    }
                    catch (Exception ex)
                    {
                        _report.Warnings.Add($"Warning: Could not delete original XML file after conversion: {ex.Message}. Manual cleanup may be needed.");
                    }
                }

                _report.Success = true;
            }
            catch (Exception ex) when (!(ex is ConfigConversionException))
            {
                _report.Success = false;
                _report.ErrorMessage = ex.Message;
                _report.Exception = ex;

                // Rollback: Delete any partial JSON file
                try
                {
                    if (System.IO.File.Exists(jsonConfigPath))
                    {
                        System.IO.File.Delete(jsonConfigPath);
                    }
                }
                catch
                {
                    // Ignore deletion errors during rollback
                }

                // Rollback: Restore XML from backup if backup exists
                if (_report.BackupCreated && System.IO.File.Exists(backupPath))
                {
                    try
                    {
                        System.IO.File.Copy(backupPath, xmlConfigPath, overwrite: true);
                        _report.Warnings.Add("Original configuration file restored from backup due to conversion failure.");
                    }
                    catch (Exception restoreEx)
                    {
                        _report.Warnings.Add($"Error: Could not restore configuration from backup: {restoreEx.Message}. Backup available at: {backupPath}");
                    }
                }

                throw new ConfigConversionException($"Failed to convert XML configuration to JSON: {ex.Message}", ex);
            }
        }

        private JsonObject ConvertLicenseSettings(XmlElement licenseSection)
        {
            var license = new JsonObject();
            var licenseAttr = licenseSection.GetAttribute("license");
            license["License"] = licenseAttr ?? string.Empty;
            return license;
        }

        private JsonObject ConvertEncryptionSettings(XmlElement encryptionSection)
        {
            var encryption = new JsonObject();

            // Get encryption key attribute
            var keyAttr = encryptionSection.GetAttribute("encryptionKey");
            encryption["EncryptionKey"] = keyAttr ?? "default";

            // Convert RSA keys
            var rsaKeysArray = new JsonArray();
            var rsaKeysElement = encryptionSection.SelectSingleNode("RSAKeys") as XmlElement;
            if (rsaKeysElement != null)
            {
                foreach (XmlElement keySettings in rsaKeysElement.SelectNodes("KeySettings"))
                {
                    var keyObj = new JsonObject();
                    keyObj["Name"] = keySettings.GetAttribute("name") ?? string.Empty;
                    keyObj["PublicKey"] = keySettings.GetAttribute("publicKey");
                    keyObj["PrivateKey"] = keySettings.GetAttribute("privateKey");
                    rsaKeysArray.Add(keyObj);
                }
            }

            encryption["RSAKeys"] = rsaKeysArray;
            return encryption;
        }

        private JsonObject ConvertHoneyPotSettings(XmlElement honeyPotSection)
        {
            var honeyPot = new JsonObject();
            var honeyPotsArray = new JsonArray();

            var honeyPotsElement = honeyPotSection.SelectSingleNode("HoneyPots") as XmlElement;
            if (honeyPotsElement != null)
            {
                foreach (XmlElement honeyPotItem in honeyPotsElement.SelectNodes("HoneyPot"))
                {
                    var honeyPotObj = new JsonObject();
                    honeyPotObj["SamAccountName"] = honeyPotItem.GetAttribute("samAccountName");
                    honeyPotObj["DistinguishedName"] = honeyPotItem.GetAttribute("distinguishedName");
                    honeyPotsArray.Add(honeyPotObj);
                }
            }

            honeyPot["HoneyPots"] = honeyPotsArray;
            return honeyPot;
        }

        private JsonObject ConvertInfrastructureSettings(XmlElement infrastructureSection)
        {
            var infrastructure = new JsonObject();
            var riverbedsArray = new JsonArray();

            var riverbedsElement = infrastructureSection.SelectSingleNode("Riverbeds") as XmlElement;
            if (riverbedsElement != null)
            {
                foreach (XmlElement riverbed in riverbedsElement.SelectNodes("Riverbed"))
                {
                    var riverbedObj = new JsonObject();
                    riverbedObj["SamAccountName"] = riverbed.GetAttribute("samAccountName") ?? string.Empty;
                    riverbedsArray.Add(riverbedObj);
                }
            }

            infrastructure["Riverbeds"] = riverbedsArray;
            return infrastructure;
        }

        private JsonObject ConvertCustomRulesSettings(XmlElement customRulesSection)
        {
            var customRules = new JsonObject();
            var customRulesArray = new JsonArray();

            var customRulesElement = customRulesSection.SelectSingleNode("CustomRules") as XmlElement;
            if (customRulesElement != null)
            {
                foreach (XmlElement customRule in customRulesElement.SelectNodes("CustomRule"))
                {
                    var customRuleObj = new JsonObject();
                    customRuleObj["RiskId"] = customRule.GetAttribute("RiskId") ?? string.Empty;
                    customRuleObj["MaturityLevel"] = null;

                    var computationsArray = new JsonArray();
                    var computationsElement = customRule.SelectSingleNode("Computations") as XmlElement;
                    if (computationsElement != null)
                    {
                        foreach (XmlElement computation in computationsElement.SelectNodes("Computation"))
                        {
                            var computationObj = new JsonObject();
                            computationObj["Type"] = computation.GetAttribute("Type") ?? string.Empty;

                            var scoreAttr = computation.GetAttribute("Score");
                            computationObj["Score"] = scoreAttr != null && int.TryParse(scoreAttr, out int score) ? score : 0;

                            var thresholdAttr = computation.GetAttribute("Threshold");
                            if (thresholdAttr != null && int.TryParse(thresholdAttr, out int threshold))
                            {
                                computationObj["Threshold"] = threshold;
                            }

                            var orderAttr = computation.GetAttribute("Order");
                            computationObj["Order"] = orderAttr != null && int.TryParse(orderAttr, out int order) ? order : 1;

                            computationsArray.Add(computationObj);
                        }
                    }

                    customRuleObj["Computations"] = computationsArray;
                    customRulesArray.Add(customRuleObj);
                }
            }

            customRules["CustomRules"] = customRulesArray;
            return customRules;
        }

        private JsonObject ConvertBrandSettings(XmlElement appSettings)
        {
            var brand = new JsonObject();
            brand["BrandLogo"] = null;
            brand["BrandCss"] = null;
            brand["BrandJs"] = null;

            foreach (XmlElement add in appSettings.SelectNodes("add"))
            {
                var key = add.GetAttribute("key");
                var value = add.GetAttribute("value");

                if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(value))
                {
                    continue;
                }

                switch (key)
                {
                    case "BrandLogo":
                        brand["BrandLogo"] = value;
                        break;
                    case "BrandCss":
                        brand["BrandCss"] = value;
                        break;
                    case "BrandJs":
                        brand["BrandJs"] = value;
                        break;
                }
            }

            return brand;
        }

        private JsonObject ConvertSmtpSettings(XmlElement systemNet)
        {
            var mailSettings = systemNet.SelectSingleNode("mailSettings") as XmlElement;
            if (mailSettings == null)
            {
                return null;
            }

            var smtp = mailSettings.SelectSingleNode("smtp") as XmlElement;
            if (smtp == null)
            {
                return null;
            }

            var smtpObj = new JsonObject();
            smtpObj["From"] = smtp.GetAttribute("from") ?? "from@address.com";
            smtpObj["DeliveryMethod"] = smtp.GetAttribute("deliveryMethod") ?? "Network";

            var network = smtp.SelectSingleNode("network") as XmlElement;
            if (network != null)
            {
                smtpObj["Host"] = network.GetAttribute("host") ?? "stmp.server.com";

                var portAttr = network.GetAttribute("port");
                smtpObj["Port"] = portAttr != null && int.TryParse(portAttr, out int port) ? port : 25;

                smtpObj["UserName"] = network.GetAttribute("userName") ?? "username";
                smtpObj["Password"] = network.GetAttribute("password") ?? "password";
            }
            else
            {
                smtpObj["Host"] = "stmp.server.com";
                smtpObj["Port"] = 25;
                smtpObj["UserName"] = "username";
                smtpObj["Password"] = "password";
            }

            return smtpObj;
        }

        /// <summary>
        /// Detect custom/unmapped XML sections that aren't in the standard schema
        /// </summary>
        private void DetectUnmappedCustomSections(XmlElement root, JsonObject jsonObject)
        {
            var standardSections = new HashSet<string>
            {
                "configSections", "LicenseSettings", "encryptionSettings", "honeyPotSettings",
                "infrastructureSettings", "customRulesSettings", "appSettings", "system.net",
                "runtime", "startup", "configuration"
            };

            var unmappedSections = new List<XmlElement>();
            foreach (XmlNode node in root.ChildNodes)
            {
                if (node is XmlElement element && !standardSections.Contains(element.Name))
                {
                    unmappedSections.Add(element);
                }
            }

            if (unmappedSections.Any())
            {
                var unmappedObj = new JsonObject();

                foreach (var section in unmappedSections)
                {
                    try
                    {
                        // Convert the unmapped XML element to JSON recursively
                        var jsonValue = ConvertXmlElementToJson(section);
                        unmappedObj[section.Name] = jsonValue;
                        _report.UnmappedSettings[section.Name] = section.OuterXml;
                    }
                    catch
                    {
                        _report.Warnings.Add($"Could not fully serialize custom section: {section.Name}");
                    }
                }

                if (unmappedObj.Count > 0)
                {
                    jsonObject["_unmappedXmlSettings"] = unmappedObj;
                }
            }
        }

        /// <summary>
        /// Recursively converts an XML element to a JSON value (object, array, or primitive)
        /// </summary>
        private JsonNode ConvertXmlElementToJson(XmlElement element)
        {
            var jsonObject = new JsonObject();

            // Add attributes as properties
            if (element.Attributes.Count > 0)
            {
                var attributesObj = new JsonObject();
                foreach (XmlAttribute attr in element.Attributes)
                {
                    attributesObj[attr.Name] = attr.Value;
                }

                if (attributesObj.Count > 0)
                {
                    jsonObject["_attributes"] = attributesObj;
                }
            }

            // Group child elements by name to handle arrays
            var childElements = new Dictionary<string, List<XmlElement>>();
            string textContent = string.Empty;

            foreach (XmlNode child in element.ChildNodes)
            {
                if (child is XmlElement childElement)
                {
                    if (!childElements.ContainsKey(childElement.Name))
                    {
                        childElements[childElement.Name] = new List<XmlElement>();
                    }

                    childElements[childElement.Name].Add(childElement);
                }
                else if (child is XmlText textNode)
                {
                    string trimmedText = textNode.Value.Trim();
                    if (!string.IsNullOrEmpty(trimmedText))
                    {
                        textContent += trimmedText;
                    }
                }
            }

            // Add child elements
            foreach (var kvp in childElements)
            {
                string elementName = kvp.Key;
                List<XmlElement> elements = kvp.Value;

                if (elements.Count == 1)
                {
                    // Single element - add as object
                    jsonObject[elementName] = ConvertXmlElementToJson(elements[0]);
                }
                else
                {
                    // Multiple elements with same name - add as array
                    var jsonArray = new JsonArray();
                    foreach (var elem in elements)
                    {
                        jsonArray.Add(ConvertXmlElementToJson(elem));
                    }

                    jsonObject[elementName] = jsonArray;
                }
            }

            // If element has text content and no child elements, return the text value
            if (!string.IsNullOrEmpty(textContent) && childElements.Count == 0 && element.Attributes.Count == 0)
            {
                return JsonValue.Create(textContent);
            }

            // If element has text content and child elements/attributes, add text as property
            if (!string.IsNullOrEmpty(textContent) && (childElements.Count > 0 || element.Attributes.Count > 0))
            {
                jsonObject["_text"] = textContent;
            }

            return jsonObject;
        }
    }
}
