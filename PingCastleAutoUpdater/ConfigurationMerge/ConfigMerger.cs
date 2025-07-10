namespace PingCastleAutoUpdater.ConfigurationMerge
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Xml.Linq;

    /// <summary>
    /// Implements deep XML configuration merging, preserving existing values in the target
    /// while adding new elements from the source at any nesting level.
    /// </summary>
    public class ConfigMerger : IConfigMerger
    {
        private int _recursionDepth;
        private const int MaxRecursionDepth = 100;

        /// <summary>
        /// Merges source configuration into target configuration, adding missing elements at all nesting levels
        /// </summary>
        /// <param name="target">Target configuration document</param>
        /// <param name="source">Source configuration document</param>
        /// <returns>The merged configuration document</returns>
        public XDocument MergeConfigs(XDocument target, XDocument source)
        {
            if (target == null) throw new ArgumentNullException(nameof(target));
            if (source == null) throw new ArgumentNullException(nameof(source));

            var targetRoot = target.Root;
            var sourceRoot = source.Root;

            if (targetRoot == null || sourceRoot == null)
                throw new ConfigException("Invalid configuration document structure");

            // Create a cache of existing comments in the target document
            var existingComments = GetAllComments(target);

            // Perform deep merge starting from the root elements
            MergeElements(targetRoot, sourceRoot, existingComments);

            return target;
        }

        /// <summary>
        /// Recursively merges elements from source into target
        /// </summary>
        private void MergeElements(XElement target, XElement source, HashSet<string> existingComments)
        {
            _recursionDepth++;
            if (_recursionDepth > MaxRecursionDepth)
            {
                throw new ConfigException("Document too complex for merge.");
            }

            try
            {
                foreach (var sourceElement in source.Elements())
                {
                    // Try to find a matching element in the target
                    var elementName = sourceElement.Name;

                    var matchingElements = target.Elements(elementName);

                    // Find element with matching attributes
                    var targetElement = matchingElements.FirstOrDefault(e =>
                        HasMatchingAttributes(e, sourceElement));

                    if (targetElement == null)
                    {
                        AddMissingElementWithComments(target, sourceElement, existingComments);
                    }
                    else
                    {
                        // Element exists, recursively merge its children
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
        private static bool HasMatchingAttributes(XElement first, XElement second)
        {
            // If either element has no attributes, only match on name
            if (!first.HasAttributes && !second.HasAttributes)
                return true;

            // Check that all attributes match -  partial matches are not processed.
            foreach (var attr in first.Attributes())
            {
                var secondAttr = second.Attribute(attr.Name);
                if (secondAttr == null || secondAttr.Value != attr.Value)
                    return false;
            }

            return true;
        }

        private static void AddMissingElementWithComments(XElement target, XElement sourceElement, HashSet<string> existingComments)
        {
            // Add missing comments
            var precedingComments = GetPrecedingComments(sourceElement);
            foreach (var comment in precedingComments)
            {
                if (!existingComments.Contains(comment.Value))
                {
                    target.Add(new XComment(comment.Value));
                    existingComments.Add(comment.Value);
                }
            }

            target.Add(new XElement(sourceElement));
        }

        /// <summary>
        /// Collects all comments from the document into a hashset for duplicate checking
        /// </summary>
        private static HashSet<string> GetAllComments(XDocument document)
        {
            return new HashSet<string>(
                document.Descendants()
                    .SelectMany(e => e.Nodes().OfType<XComment>())
                    .Select(c => c.Value));
        }

        /// <summary>
        /// Gets all comment nodes that directly precede the specified element
        /// </summary>
        private static IEnumerable<XComment> GetPrecedingComments(XElement element)
        {
            var comments = new List<XComment>();
            var previousNode = element.PreviousNode;

            while (previousNode != null && previousNode is XComment)
            {
                comments.Add((XComment)previousNode);
                previousNode = previousNode.PreviousNode;
            }

            // Return comments in the original order
            comments.Reverse();
            return comments;
        }
    }
}