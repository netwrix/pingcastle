namespace PingCastleAutoUpdater.ConfigurationMerge
{
    using System;

    public class ConfigMergeService
    {
        private readonly IConfigLoader _configLoader;
        private readonly IConfigMerger _configMerger;
        private readonly IConfigSaver _configSaver;

        public ConfigMergeService(
            IConfigLoader configLoader,
            IConfigMerger configMerger,
            IConfigSaver configSaver)
        {
            _configLoader = configLoader;
            _configMerger = configMerger;
            _configSaver = configSaver;
        }

        public void MergeConfigFiles(string targetPath, string sourcePath)
        {
            if(targetPath == null) throw new ArgumentNullException(nameof(targetPath));
            if(sourcePath == null) throw new ArgumentNullException(nameof(sourcePath));

            var targetConfig = _configLoader.LoadConfig(targetPath);
            var sourceConfig = _configLoader.LoadConfig(sourcePath);

            var mergedConfig = _configMerger.MergeConfigs(targetConfig, sourceConfig);

            _configSaver.SaveConfig(mergedConfig, targetPath);
        }
    }
}