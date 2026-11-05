namespace PingCastleAutoUpdater.ConfigurationMerge
{
    using System;
    using System.Collections.Generic;
    using System.Xml;

    /// <summary>
    /// Implements deep XML configuration merging, preserving existing values in the target
    /// while adding new elements from the source at any nesting level.
    /// </summary>
    public class ConfigMerger : IConfigMerger
    {
        private const int MaxRecursionDepth = 100;
        private int _recursionDepth;
        private List<string> _mergedElements;
        private List<string> _newElements;

        /// <summary>
        /// Gets the list of elements that were merged (already existed in target)
        /// </summary>
        public IReadOnlyList<string> MergedElements => _mergedElements?.AsReadOnly() ?? new List<string>().AsReadOnly();

        /// <summary>
        /// Gets the list of elements that were added (new from source)
        /// </summary>
        public IReadOnlyList<string> NewElements => _newElements?.AsReadOnly() ?? new List<string>().AsReadOnly();

        /// <summary>
        /// Merges source configuration into target configuration, adding missing elements at all nesting levels
        /// </summary>
        /// <param name="target">Target configuration document</param>
        /// <param name="source">Source configuration document</param>
        /// <returns>The merged configuration document</returns>
        public XmlDocument MergeConfigs(XmlDocument target, XmlDocument source)
        {
            if (target == null)
            {
                throw new ArgumentNullException(nameof(target));
            }

            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            // Reset tracking lists
            _mergedElements = new List<string>();
            _newElements = new List<string>();

            var targetRoot = target.DocumentElement;
            var sourceRoot = source.DocumentElement;

            if (targetRoot == null || sourceRoot == null)
            {
                throw new ConfigException("Invalid configuration document structure");
            }

            // Create a cache of existing comments in the target document
            var existingComments = GetAllComments(target);

            // Perform deep merge starting from the root elements
            MergeElements(targetRoot, sourceRoot, existingComments);

            return target;
        }

        /// <summary>
        /// Recursively merges elements from source into target
        /// </summary>
        private void MergeElements(XmlElement target, XmlElement source, HashSet<string> existingComments)
        {
            _recursionDepth++;
            if (_recursionDepth > MaxRecursionDepth)
            {
                throw new ConfigException("Document too complex for merge.");
            }

            try
            {
                foreach (XmlNode node in source.ChildNodes)
                {
                    if (node.NodeType != XmlNodeType.Element)
                    {
                        continue;
                    }

                    var sourceElement = (XmlElement)node;
                    var elementName = sourceElement.LocalName;

                    // Find element with matching attributes
                    XmlElement targetElement = null;
                    foreach (XmlNode candidateNode in target.ChildNodes)
                    {
                        if (candidateNode.NodeType != XmlNodeType.Element)
                        {
                            continue;
                        }

                        var candidate = (XmlElement)candidateNode;
                        if (candidate.LocalName == elementName && HasMatchingAttributes(candidate, sourceElement))
                        {
                            targetElement = candidate;
                            break;
                        }
                    }

                    if (targetElement == null)
                    {
                        AddMissingElementWithComments(target, sourceElement, existingComments);
                        _newElements.Add(elementName);
                    }
                    else
                    {
                        // Element exists, recursively merge its children
                        _mergedElements.Add(elementName);
                        MergeElements(targetElement, sourceElement, existingComments);
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

        private static bool HasMatchingAttributes(XmlElement first, XmlElement second)
        {
            // If either element has no attributes, only match on name
            if (first.Attributes.Count == 0 && second.Attributes.Count == 0)
            {
                return true;
            }

            // Check that all attributes match -  partial matches are not processed.
            foreach (XmlAttribute attr in first.Attributes)
            {
                var secondAttr = second.GetAttributeNode(attr.Name);
                if (secondAttr == null || secondAttr.Value != attr.Value)
                {
                    return false;
                }
            }

            return true;
        }

        private static void AddMissingElementWithComments(XmlElement target, XmlElement sourceElement, HashSet<string> existingComments)
        {
            // Add missing comments
            var precedingComments = GetPrecedingComments(sourceElement);
            foreach (var comment in precedingComments)
            {
                if (!existingComments.Contains(comment))
                {
                    var commentNode = target.OwnerDocument.CreateComment(comment);
                    target.AppendChild(commentNode);
                    existingComments.Add(comment);
                }
            }

            // Clone and append the source element
            var newElement = (XmlElement)target.OwnerDocument.ImportNode(sourceElement, true);
            target.AppendChild(newElement);
        }

        /// <summary>
        /// Collects all comments from the document into a hashset for duplicate checking
        /// </summary>
        private static HashSet<string> GetAllComments(XmlDocument document)
        {
            var comments = new HashSet<string>();
            CollectComments(document.DocumentElement, comments);
            return comments;
        }

        private static void CollectComments(XmlNode node, HashSet<string> comments)
        {
            foreach (XmlNode child in node.ChildNodes)
            {
                if (child.NodeType == XmlNodeType.Comment)
                {
                    comments.Add(child.Value);
                }
                else if (child.NodeType == XmlNodeType.Element)
                {
                    CollectComments(child, comments);
                }
            }
        }

        /// <summary>
        /// Gets all comment nodes that directly precede the specified element
        /// </summary>
        private static List<string> GetPrecedingComments(XmlElement element)
        {
            var comments = new List<string>();
            var previousNode = element.PreviousSibling;

            while (previousNode != null && previousNode.NodeType == XmlNodeType.Comment)
            {
                comments.Add(previousNode.Value);
                previousNode = previousNode.PreviousSibling;
            }

            // Return comments in the original order
            comments.Reverse();
            return comments;
        }
    }
}