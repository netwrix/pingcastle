//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using System.Xml.Serialization;

namespace PingCastle.Data
{
    public static class JsonExportHelper
    {
        public static JsonSerializerOptions CreateOptions()
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = null, // preserve original property names
                TypeInfoResolver = new DefaultJsonTypeInfoResolver
                {
                    Modifiers = { ApplyShouldSerializeAndXmlIgnore }
                },
                Converters = { new JsonStringEnumConverter() }
            };
            return options;
        }

        private static void ApplyShouldSerializeAndXmlIgnore(JsonTypeInfo typeInfo)
        {
            if (typeInfo.Kind != JsonTypeInfoKind.Object)
            {
                return;
            }

            for (int i = typeInfo.Properties.Count - 1; i >= 0; i--)
            {
                var property = typeInfo.Properties[i];
                var clrProperty = typeInfo.Type.GetProperty(property.Name,
                    BindingFlags.Public | BindingFlags.Instance);

                if (clrProperty == null)
                {
                    continue;
                }

                // Honor [XmlIgnore] + [IgnoreDataMember] attributes by removing the property
                // entirely. Just setting ShouldSerialize = false leaves the property registered
                // under its original name, which collides when another property is renamed onto
                // it via [XmlArray]/[XmlElement] (e.g. InstalledHotFixes vs InstalledHotFixesArray).
                if (clrProperty.GetCustomAttribute<XmlIgnoreAttribute>() != null
                    || clrProperty.GetCustomAttribute<IgnoreDataMemberAttribute>() != null)
                {
                    typeInfo.Properties.RemoveAt(i);
                    continue;
                }

                // Honor [XmlElement] / [XmlArray] ElementName so JSON field names match XML output
                // (e.g., CategoryAsString -> Category)
                var xmlElement = clrProperty.GetCustomAttribute<XmlElementAttribute>();
                if (xmlElement != null && !string.IsNullOrEmpty(xmlElement.ElementName))
                {
                    property.Name = xmlElement.ElementName;
                }
                else
                {
                    var xmlArray = clrProperty.GetCustomAttribute<XmlArrayAttribute>();
                    if (xmlArray != null && !string.IsNullOrEmpty(xmlArray.ElementName))
                    {
                        property.Name = xmlArray.ElementName;
                    }
                }

                // Honor ShouldSerialize*() methods (XmlSerializer convention)
                var shouldSerializeMethod = typeInfo.Type.GetMethod(
                    "ShouldSerialize" + property.Name,
                    BindingFlags.Public | BindingFlags.Instance,
                    null,
                    Type.EmptyTypes,
                    null);

                if (shouldSerializeMethod != null && shouldSerializeMethod.ReturnType == typeof(bool))
                {
                    property.ShouldSerialize = (obj, _) =>
                    {
                        return (bool)shouldSerializeMethod.Invoke(obj, null);
                    };
                }
            }
        }
    }
}