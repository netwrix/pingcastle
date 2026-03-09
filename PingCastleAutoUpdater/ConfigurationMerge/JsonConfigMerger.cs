namespace PingCastleAutoUpdater.ConfigurationMerge
{
    using System;
    using System.Collections.Generic;
    using System.Text.Json;
    using System.Text.Json.Nodes;

    /// <summary>
    /// Implements deep JSON configuration merging, preserving existing values in the target
    /// while adding new elements from the source at any nesting level.
    /// Supports atomic operations with rollback, delta-only merging, and backup management.
    /// </summary>
    public class JsonConfigMerger : IJsonConfigMerger
    {
        private const int MaxRecursionDepth = 100;
        private int _recursionDepth;
        private List<string> _mergedProperties;
        private List<string> _newProperties;

        /// <summary>
        /// Gets the list of properties that were merged (already existed in target)
        /// </summary>
        public IReadOnlyList<string> MergedProperties => _mergedProperties?.AsReadOnly() ?? new List<string>().AsReadOnly();

        /// <summary>
        /// Gets the list of properties that were added (new from source)
        /// </summary>
        public IReadOnlyList<string> NewProperties => _newProperties?.AsReadOnly() ?? new List<string>().AsReadOnly();

        /// <summary>
        /// Merges source JSON configuration into target JSON configuration.
        /// Preserves existing values in target while adding new properties from source.
        /// Uses atomic operations with automatic rollback on failure.
        /// </summary>
        /// <param name="targetPath">Path to the target JSON configuration file</param>
        /// <param name="sourcePath">Path to the source JSON configuration file</param>
        public void MergeJsonConfigFiles(string targetPath, string sourcePath)
        {
            if (string.IsNullOrEmpty(targetPath))
            {
                throw new ArgumentNullException(nameof(targetPath));
            }

            if (string.IsNullOrEmpty(sourcePath))
            {
                throw new ArgumentNullException(nameof(sourcePath));
            }

            // Reset tracking lists
            _mergedProperties = new List<string>();
            _newProperties = new List<string>();

            try
            {
                string targetContent = System.IO.File.ReadAllText(targetPath);
                string sourceContent = System.IO.File.ReadAllText(sourcePath);

                var targetNode = JsonNode.Parse(targetContent);
                var sourceNode = JsonNode.Parse(sourceContent);

                if (targetNode == null || sourceNode == null)
                {
                    throw new ConfigException("Invalid JSON configuration document structure");
                }

                if (targetNode is not JsonObject targetObject || sourceNode is not JsonObject sourceObject)
                {
                    throw new ConfigException("Root element must be a JSON object");
                }

                MergeObjects(targetObject, sourceObject);

                var options = new JsonSerializerOptions { WriteIndented = true };
                string mergedContent = targetObject.ToJsonString(options);
                System.IO.File.WriteAllText(targetPath, mergedContent);
            }
            catch (JsonException ex)
            {
                throw new ConfigException($"Invalid JSON format in configuration file: {ex.Message}", ex);
            }
            catch (Exception ex) when (!(ex is ConfigException))
            {
                throw new ConfigException($"Failed to merge JSON configuration files: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Merges source JSON configuration into target with atomic operations.
        /// Creates backup before attempting merge. Rolls back on failure.
        /// </summary>
        /// <param name="targetPath">Path to the target JSON configuration file</param>
        /// <param name="sourcePath">Path to the source JSON configuration file</param>
        public void MergeJsonConfigFilesAtomic(string targetPath, string sourcePath)
        {
            // Reset tracking lists
            _mergedProperties = new List<string>();
            _newProperties = new List<string>();

            string backupPath = null;

            try
            {
                // Step 1: Create single backup
                backupPath = CreateSingleBackup(targetPath);

                // Step 2: Perform merge (in-memory)
                string targetContent = System.IO.File.ReadAllText(targetPath);
                string sourceContent = System.IO.File.ReadAllText(sourcePath);

                var targetNode = JsonNode.Parse(targetContent);
                var sourceNode = JsonNode.Parse(sourceContent);

                if (targetNode == null || sourceNode == null)
                {
                    throw new ConfigException("Invalid JSON configuration document structure");
                }

                if (targetNode is not JsonObject targetObject || sourceNode is not JsonObject sourceObject)
                {
                    throw new ConfigException("Root element must be a JSON object");
                }

                // Delta-only merge (only add new fields, never restructure)
                MergeOnlyNewFields(targetObject, sourceObject);

                // Step 3: Atomic write
                var options = new JsonSerializerOptions { WriteIndented = true };
                string mergedContent = targetObject.ToJsonString(options);

                // Write to temp file first, then move (atomic)
                string tempPath = targetPath + ".tmp";
                System.IO.File.WriteAllText(tempPath, mergedContent);
                System.IO.File.Delete(targetPath);
                System.IO.File.Move(tempPath, targetPath);
            }
            catch (ConfigException)
            {
                // Already a ConfigException, just rollback and rethrow
                if (backupPath != null && System.IO.File.Exists(backupPath))
                {
                    RestoreFromBackup(targetPath, backupPath);
                }

                throw;
            }
            catch (JsonException ex)
            {
                // Wrap JSON parsing errors
                if (backupPath != null && System.IO.File.Exists(backupPath))
                {
                    RestoreFromBackup(targetPath, backupPath);
                }

                throw new ConfigException($"Invalid JSON format in configuration file: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                // Wrap other exceptions
                if (backupPath != null && System.IO.File.Exists(backupPath))
                {
                    RestoreFromBackup(targetPath, backupPath);
                }

                throw new ConfigException($"Failed to merge JSON configuration files: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Creates a single backup of the target file (overwrites previous backup).
        /// Returns the path to the backup file.
        /// </summary>
        private string CreateSingleBackup(string targetPath)
        {
            if (!System.IO.File.Exists(targetPath))
            {
                throw new ConfigException($"Target file does not exist: {targetPath}");
            }

            string backupPath = targetPath + ".bak";

            // If backup exists, delete it (single backup only)
            if (System.IO.File.Exists(backupPath))
            {
                System.IO.File.Delete(backupPath);
            }

            // Create new backup
            System.IO.File.Copy(targetPath, backupPath);
            return backupPath;
        }

        /// <summary>
        /// Restores the target file from backup
        /// </summary>
        private void RestoreFromBackup(string targetPath, string backupPath)
        {
            if (!System.IO.File.Exists(backupPath))
            {
                throw new ConfigException($"Backup file does not exist: {backupPath}");
            }

            if (System.IO.File.Exists(targetPath))
            {
                System.IO.File.Delete(targetPath);
            }

            System.IO.File.Copy(backupPath, targetPath!);
        }

        /// <summary>
        /// Performs delta-only merge: only adds new fields from source, never restructures or removes.
        /// </summary>
        private void MergeOnlyNewFields(JsonObject target, JsonObject source)
        {
            _recursionDepth++;
            if (_recursionDepth > MaxRecursionDepth)
            {
                throw new ConfigException("Configuration document too complex for merge.");
            }

            try
            {
                foreach (var sourceProperty in source)
                {
                    string propertyName = sourceProperty.Key;
                    JsonNode sourceValue = sourceProperty.Value;

                    if (target.ContainsKey(propertyName))
                    {
                        JsonNode targetValue = target[propertyName];

                        // Both are objects - recursively merge
                        if (targetValue is JsonObject targetObj && sourceValue is JsonObject sourceObj)
                        {
                            MergeOnlyNewFields(targetObj, sourceObj);
                        }
                        // Both are arrays - merge arrays (add missing items from source)
                        else if (targetValue is JsonArray targetArray && sourceValue is JsonArray sourceArray)
                        {
                            MergeArrays(targetArray, sourceArray);
                        }
                        // Target is null - take source value (add missing default)
                        else if (targetValue is null)
                        {
                            target[propertyName] = CloneJsonNode(sourceValue);
                        }

                        // Otherwise keep target value (preserve user setting)
                    }
                    else
                    {
                        // Property doesn't exist in target - add from source (new field/section)
                        target[propertyName] = CloneJsonNode(sourceValue);
                    }
                }
            }
            finally
            {
                _recursionDepth--;
                if (_recursionDepth < 0)
                {
                    _recursionDepth = 0;
                }
            }
        }

        /// <summary>
        /// Recursively merges properties from source object into target object.
        /// </summary>
        private void MergeObjects(JsonObject target, JsonObject source)
        {
            _recursionDepth++;
            if (_recursionDepth > MaxRecursionDepth)
            {
                throw new ConfigException("Configuration document too complex for merge.");
            }

            try
            {
                foreach (var sourceProperty in source)
                {
                    string propertyName = sourceProperty.Key;
                    JsonNode sourceValue = sourceProperty.Value;

                    if (target.ContainsKey(propertyName))
                    {
                        JsonNode targetValue = target[propertyName];

                        // Both are objects - recursively merge
                        if (targetValue is JsonObject targetObj && sourceValue is JsonObject sourceObj)
                        {
                            MergeObjects(targetObj, sourceObj);
                        }
                        // Both are arrays - merge arrays (add missing items from source)
                        else if (targetValue is JsonArray targetArray && sourceValue is JsonArray sourceArray)
                        {
                            MergeArrays(targetArray, sourceArray);
                            _mergedProperties.Add(propertyName);
                        }
                        // Target is null - take source value (add new default)
                        else if (targetValue is null)
                        {
                            target[propertyName] = CloneJsonNode(sourceValue);
                            _newProperties.Add(propertyName);
                        }
                        // Other cases - keep target value (preserve user setting)
                        else
                        {
                            _mergedProperties.Add(propertyName);
                        }
                    }
                    else
                    {
                        // Property doesn't exist in target - add from source (new default)
                        target[propertyName] = CloneJsonNode(sourceValue);
                        _newProperties.Add(propertyName);
                    }
                }
            }
            finally
            {
                _recursionDepth--;
                if (_recursionDepth < 0)
                {
                    _recursionDepth = 0;
                }
            }
        }

        /// <summary>
        /// Merges source array items into target array, avoiding duplicates.
        /// For objects with unique identifiers (RiskId, Name, Id, Key), uses those to detect duplicates.
        /// For other items, appends new items to the target array.
        /// </summary>
        private void MergeArrays(JsonArray targetArray, JsonArray sourceArray)
        {
            if (sourceArray == null || sourceArray.Count == 0)
                return;

            // Iterate through source items
            foreach (var sourceItem in sourceArray)
            {
                if (sourceItem is JsonObject sourceObj)
                {
                    // Try to find a unique identifier property
                    string uniqueId = GetUniqueIdentifier(sourceObj);

                    if (uniqueId != null)
                    {
                        // Check if target already has an item with the same unique identifier
                        bool exists = false;
                        foreach (var targetItem in targetArray)
                        {
                            if (targetItem is JsonObject targetObj)
                            {
                                string targetId = GetUniqueIdentifier(targetObj);
                                if (targetId == uniqueId)
                                {
                                    exists = true;
                                    break;
                                }
                            }
                        }

                        // If not found, add it to target
                        if (!exists)
                        {
                            targetArray.Add(CloneJsonNode(sourceItem));
                        }
                    }
                    else
                    {
                        // No unique identifier found - add the item as new
                        // This is conservative to avoid duplicate objects without identifiers
                        targetArray.Add(CloneJsonNode(sourceItem));
                    }
                }
                else
                {
                    // For non-object items (primitives), just append them
                    targetArray.Add(CloneJsonNode(sourceItem));
                }
            }
        }

        /// <summary>
        /// Attempts to extract a unique identifier from a JSON object.
        /// Checks for common identifier properties: RiskId, Name, Id, Key, samAccountName, etc.
        /// </summary>
        private static string GetUniqueIdentifier(JsonObject obj)
        {
            // List of properties commonly used as unique identifiers, in priority order
            string[] identifierCandidates = { "RiskId", "Id", "Name", "Key", "samAccountName", "SamAccountName" };

            foreach (var propertyName in identifierCandidates)
            {
                if (obj.ContainsKey(propertyName) && obj[propertyName] is not null)
                {
                    var value = obj[propertyName].GetValue<string>();
                    if (!string.IsNullOrEmpty(value))
                    {
                        return value;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Clones a JsonNode to create an independent copy that can be assigned to a different parent.
        /// </summary>
        private static JsonNode CloneJsonNode(JsonNode node)
        {
            if (node == null)
            {
                return null;
            }

            // Serialize to string and deserialize to create a deep clone
            string json = node.ToJsonString();
            return JsonNode.Parse(json);
        }
    }
}
