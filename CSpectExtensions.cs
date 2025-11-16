using Plugin;

public static class iCSpectExtensions
{
    static public ushort ReadWord(this iCSpect cspect, ushort address)
    {
        return (ushort)(cspect.Peek(address) | (cspect.Peek((ushort)(address + 1)) << 8));
    }
}