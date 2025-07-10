namespace PingCastle.Exports
{
    public interface IExport
    {
        void Initialize(RuntimeSettings initialisationSettings);
        void Export(string filename);
        string Name { get; }
        string Description { get; }
        DisplayState QueryForAdditionalParameterInInteractiveMode();
    }
}
