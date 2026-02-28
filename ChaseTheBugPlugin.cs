using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Messaging;
using System.Text;
using Plugin;


namespace ChaseTheBug
{

    public struct TraceRange
    {
        public ushort TraceStart { get; set; }
        public ushort TraceEnd { get; set; }

        public TraceRange(ushort traceStart, ushort traceEnd)
        {
            TraceStart = traceStart;
            TraceEnd = traceEnd;
        }

        public override string ToString()
        {
            return $"TraceStart: 0x{TraceStart:X4}, TraceEnd: 0x{TraceEnd:X4}";
        }
    }


    public struct FunctionAddress
    {
        public string Name { get; set; }
        public bool Exit { get; set; }

        public bool IsInterrupt { get; set; }

        public FunctionAddress(string name, bool exit, bool isInterrupt = false)
        {
            Name = name;
            Exit = exit;
            IsInterrupt = isInterrupt;
        }
    }

    public struct FunctionStackEntry
    {
        public string Name { get; set; }
        public Z80Regs Regs { get; set; }

        public short TopOfStack { get; set; }

        public List<short> MMURegs { get; set; }

        public FunctionStackEntry(string name, Z80Regs regs = null, short topOfStack = 0, List<short> mmuRegs = null)
        {
            Name = name;
            Regs = regs;
            TopOfStack = topOfStack;
            MMURegs = mmuRegs;
        }
    }

    public class ChaseTheBugPlugin : iPlugin
    {
        private iCSpect cspect;

        private NextMemResolver nextMem = new NextMemResolver();

        private Z88dkMapFile symbolMap;

        private bool startWatching = false;

        private bool disabled = false;

        private List<TraceRange> additionalTraceRanges = new List<TraceRange>();

        private Dictionary<ushort, ushort> MemPoints = new Dictionary<ushort, ushort>();

        // Function address to be tracked (on entry and exit)
        private Dictionary<int, FunctionAddress> FunctionAddresses = new Dictionary<int, FunctionAddress>();

        // Function stack
        private List<FunctionStackEntry> FunctionStack = new List<FunctionStackEntry>();

        // Maximum function nesting level
        private int FnNestingLevel = 0;

        private DateTime? firstLogTime = null;

        public List<sIO> Init(iCSpect c)
        {
            cspect = c;
            LoadConfig();
            var sIOs = new List<sIO>();

            if (disabled)
            {
                Log("Plugin is disabled. Exiting initialization.");
                return sIOs;
            }

            Log("Plugin initialized.");
            Log("Loading configuration...");
            Log("Setting up memory watches...");

            // Watch MMU1 register for writes
            sIOs.Add(new sIO(0x51, eAccess.NextReg_Write));

            additionalTraceRanges.Add(new TraceRange(0x0000, 0x4000));

            var dataUserHead = symbolMap.GetSymbolByName("__data_crt_head");
            if (dataUserHead != null)
            {
                Log($"Data head at 0x{dataUserHead.Address:X4}");
                additionalTraceRanges.Add(new TraceRange(0x8000, (ushort)dataUserHead.Address));
            }
            else
            {
                Log("Warning: __data_user_head symbol not found in map file. Skipping upper memory watch setup.");
            }

            foreach (var range in additionalTraceRanges)
            {
                Log("Trace range: " + range);

                for (ushort address = range.TraceStart; address < range.TraceEnd; address++)
                {
                    sIOs.Add(new sIO(address, eAccess.Memory_Write));
                }
            }

            foreach (var memPoint in MemPoints)
            {
                sIOs.Add(new sIO(memPoint.Key, eAccess.Memory_Write));
            }

            foreach (var func in FunctionAddresses)
            {
                sIOs.Add(new sIO(func.Key, eAccess.Memory_EXE));
            }

            // Add key press 
            sIOs.Add(new sIO("<ctrl>g", eAccess.KeyPress, 0));
            sIOs.Add(new sIO("<ctrl>h", eAccess.KeyPress, 1));

            return sIOs;
        }


        public void OSTick()
        {
        }

        public short TopOfStack 
        { 
            get { 
                var sp = cspect.GetRegs().SP;
                var stackBytes = cspect.Peek(sp, 2);
                return (short)(stackBytes[0] + 256 * stackBytes[1]);
            } 
        }

        public List<short> MMURegs
        {
            get
            {
                List<short> v = new List<short>();
                for (byte reg = 0x50; reg < 0x58; reg++)
                    v.Add(cspect.GetNextRegister(reg));
                return v;              
            }
        }

        public bool Write(eAccess type, int port, int id, byte mmu1)
        {
            if (!startWatching)
                return false;
            // Attempt to write MMU register 1
            if (type == eAccess.NextReg_Write && port == 0x51)
            {
                var mmu0 = cspect.GetNextRegister(0x50);
                if (mmu0 + 1 != mmu1 && (mmu0 != 0xff || mmu1 != 0xff))
                {
                    Log($"MMU0 is {mmu0} whereas MMU1 write is {mmu1}");
                    cspect.Debugger(eDebugCommand.Enter);
                }
                else
                    Log($"MMU1 write detected: {mmu1}");
            }

            if (type == eAccess.Memory_Write)
            {
                var pc = cspect.GetRegs().PC;

                if (MemPoints.TryGetValue((ushort)port, out ushort forbiddenValue))
                {
                    if (forbiddenValue == mmu1)
                    {
                        Log($"MemPoint hit at 0x{port:X4}: forbidding value 0x{forbiddenValue:X2} write from PC 0x{pc:X4}");
                        cspect.Debugger(eDebugCommand.Enter);
                    }
                    else
                    {
                        return false;
                    }
                }


                Log($"Attempted write to 0x{port:X4} from address 0x{pc:X4}");
                cspect.Debugger(eDebugCommand.Enter);
            }

            return false;
        }

        public byte Read(eAccess type, int port, int _id, out bool isvalid)
        {
            if (type == eAccess.Memory_EXE)
            {
                FunctionAddress funcAddr;
                if (FunctionAddresses.TryGetValue(port, out funcAddr))
                {

                    if (funcAddr.Exit)
                    {
                        Log($"{new string(' ', (FunctionStack.Count) * 2)}<== {funcAddr.Name} at 0x{port:X4}, PC=0x{cspect.GetRegs().PC:X4}, Ret=0x{TopOfStack:X4}");
                        if (FunctionStack.Count > 0)
                        {
                            if (funcAddr.Name != FunctionStack[FunctionStack.Count - 1].Name)
                            {
                                Log($"Warning: Function exit for {funcAddr.Name} at 0x{port:X4} does not match top of stack {FunctionStack[FunctionStack.Count - 1]}.");
                                cspect.Debugger(eDebugCommand.Enter);
                            }
                            else
                            {
                                var fnCall = FunctionStack[FunctionStack.Count - 1];
                                var prevRegs = fnCall.Regs;
                                if (prevRegs != null)
                                {
                                    var currentRegs = cspect.GetRegs();
                                    if (!EqualRegs(prevRegs, currentRegs))
                                    {
                                        Log($"Warning: Registers differ on exit from interrupt {funcAddr.Name} at 0x{port:X4}.");
                                        Log($"Regs at entry: {prevRegs}");
                                        Log($"Regs at exit:  {currentRegs}");
                                        cspect.Debugger(eDebugCommand.Enter);
                                    }

                                    if (TopOfStack != fnCall.TopOfStack)
                                    {
                                        Log($"Warning: Top of the stack modified. Original {fnCall.TopOfStack:X4} vs {TopOfStack:X4}");
                                        cspect.Debugger(eDebugCommand.Enter);
                                    }

                                    if (!currentRegs.IFF1)
                                    {
                                        Log($"Warning: Interrupts disabled!");
                                        cspect.Debugger(eDebugCommand.Enter);
                                    }

                                    var currentMMUs = MMURegs;
                                    for (short i = 0; i < 8; i++)
                                    {
                                        if (currentMMUs[i] != fnCall.MMURegs[i])
                                        {
                                            Log($"Warning: MMU{i} modified from {fnCall.MMURegs[i]} to {MMURegs[i]}");
                                            cspect.Debugger(eDebugCommand.Enter);
                                        }
                                    }
                                }
                                FunctionStack.RemoveAt(FunctionStack.Count - 1);
                            }
                        }
                        else
                        {
                            Log($"Warning: Function exit for {funcAddr.Name} at 0x{port:X4} but function stack is empty.");
                            // cspect.Debugger(eDebugCommand.Enter);

                        }
                    }
                    else
                    {
                        FunctionStack.Add(new FunctionStackEntry(funcAddr.Name, 
                            funcAddr.IsInterrupt ? cspect.GetRegs() : null, 
                            TopOfStack,
                            MMURegs));
                        Log($"{new string(' ', (FunctionStack.Count) * 2)}==> {funcAddr.Name} at 0x{port:X4}");
                        if (FunctionStack.Count > FnNestingLevel)
                        {
                            FnNestingLevel = FunctionStack.Count;
                            Log($"New maximum function nesting level: {FnNestingLevel}, current stack: {cspect.GetRegs().SP:X4}");
                            for (int i = 0; i < FunctionStack.Count; i++)
                            {
                                Log(new string(' ', i * 2) + $"-> {FunctionStack[i].Name}");
                            }
                        }
                    }
                }
            }

            isvalid = false;
            return 0;
        }

        public bool KeyPressed(int _id)
        {
            var enabled = _id == 1 ? "enabled" : "disabled";
            Log($"MemWatch {enabled}.");
            startWatching = _id == 1;
            return true;
        }


        private void LoadConfig()
        {
            string configPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ChaseTheBug.cfg");

            if (!System.IO.File.Exists(configPath))
            {
                Log("No config file found, using defaults.");
                return;
            }

            // First we load the map file
            foreach (var line in System.IO.File.ReadLines(configPath))
            {
                if (line.StartsWith("MapFile="))
                {
                    var mapFile = line.Substring("MapFile=".Length);
                    Log("Loading map file: " + mapFile);
                    symbolMap = Z88dkMapFile.Parse(mapFile);
                    Log($"Loaded {symbolMap.Symbols.Count} symbols from map file.");
                }
            }


            foreach (var line in System.IO.File.ReadLines(configPath))
            {
                if (line.StartsWith("Disabled"))
                {
                    disabled = true;
                    return;
                }

                if (line.StartsWith("AddRange="))
                {
                    var config = line.Substring("AddRange=".Length);
                    var parts = config.Split(new char[] { '-', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);

                    if (parts.Length == 2)
                    {
                        ushort start = (ushort)ParseNumber(parts[0]);
                        ushort end = (ushort)ParseNumber(parts[1]);
                        var range = new TraceRange(start, end);
                        this.additionalTraceRanges.Add(range);
                    }
                }

                if (line.StartsWith("MemPoint="))
                {
                    var config = line.Substring("MemPoint=".Length);
                    // Split address and value, separated by comma or space
                    var parts = config.Split(new char[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);

                    ushort address = (ushort)ParseNumber(parts[0]);
                    ushort value = (ushort)ParseNumber(parts[1]);
                    this.MemPoints[address] = value;
                    Log($"Added MemPoint: Address=0x{address:X4}, Value=0x{value:X2}");
                }

                if (line.StartsWith("Fn="))
                {
                    var config = line.Substring("Fn=".Length);
                    // Split addresses separated by comma or space
                    var parts = config.Split(new char[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);

                    FunctionAddresses.Add(ParseNumber(parts[0]), new FunctionAddress(parts[0], false));
                    Log($"Added Function Entry {parts[0]} at 0x{ParseNumber(parts[0]):X4}");

                    foreach (var part in parts.Skip(1))
                    {
                        FunctionAddresses.Add(ParseNumber(part), new FunctionAddress(parts[0], true));
                        Log($"Added Function Exit {part} at 0x{ParseNumber(part):X4}");
                    }
                    Log($"Added Function {parts[0]}");
                }
                if (line.StartsWith("Int="))
                {
                    var config = line.Substring("Int=".Length);
                    // Split addresses separated by comma or space
                    var parts = config.Split(new char[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);

                    FunctionAddresses.Add(ParseNumber(parts[0]), new FunctionAddress(parts[0], false, true));
                    Log($"Added Interrupt Entry {parts[0]} at 0x{ParseNumber(parts[0]):X4}");

                    foreach (var part in parts.Skip(1))
                    {
                        FunctionAddresses.Add(ParseNumber(part), new FunctionAddress(parts[0], true, true));
                        Log($"Added Interrupt Exit {part} at 0x{ParseNumber(part):X4}");
                    }
                    Log($"Added Function {parts[0]}");
                }
            }
        }


        private int ParseNumber(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return -1;

            // Trim whitespace
            input = input.Trim();

            if (string.IsNullOrWhiteSpace(input))
                return -1;

            // Handle $-prefixed hex (assembler style)
            if (input.StartsWith("$"))
            {
                return int.Parse(input.Substring(1), NumberStyles.HexNumber);
            }

            // Handle 0x-prefixed hex (C-style)
            if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return int.Parse(input.Substring(2), NumberStyles.HexNumber);
            }

            int number;
            // Try to parse as decimal
            if (int.TryParse(input, out number))
            {
                return number;
            }

            if (symbolMap != null)
            {
                var symbol = symbolMap.GetSymbolByName(input);
                if (symbol != null)
                {
                    return symbol.Address;
                }
            }

            return -1;
        }

        public bool EqualRegs(Z80Regs regs1, Z80Regs regs2)
        {
            bool equals = true;
            if (regs1.AF != regs2.AF) { Log($"AF registers differ: {regs1.AF:X4} - {regs2.AF:X4}"); equals = false; }
            if (regs1.BC != regs2.BC) { Log($"BC registers differ: {regs1.BC:X4} - {regs2.BC:X4}"); equals = false; }
            if (regs1.DE != regs2.DE) { Log($"DE registers differ: {regs1.DE:X4} - {regs2.DE:X4}"); equals = false; }
            if (regs1.HL != regs2.HL) { Log($"HL registers differ: {regs1.HL:X4} - {regs2.HL:X4}"); equals = false; }
            if (regs1.IX != regs2.IX) { Log($"IX registers differ: {regs1.IX:X4} - {regs2.IX:X4}"); equals = false; }
            if (regs1.IY != regs2.IY) { Log($"IY registers differ: {regs1.IY:X4} - {regs2.IY:X4}"); equals = false; }
            if (regs1._AF != regs2._AF) { Log($"AF' registers differ: {regs1._AF:X4} - {regs2._AF:X4}"); equals = false; }
            if (regs1._BC != regs2._BC) { Log($"BC' registers differ: {regs1._BC:X4} - {regs2._BC:X4}"); equals = false; }
            if (regs1._DE != regs2._DE) { Log($"DE' registers differ: {regs1._DE:X4} - {regs2._DE:X4}"); equals = false; }
            if (regs1._HL != regs2._HL) { Log($"HL' registers differ: {regs1._HL:X4} - {regs2._HL:X4}"); equals = false; }
            if (regs1.SP != regs2.SP) { Log($"SP registers differ: {regs1.SP:X4} - {regs2.SP:X4}"); equals = false; }

            return equals;
        }


        private void Log(string message)
        {
            if (!firstLogTime.HasValue)
                firstLogTime = DateTime.UtcNow;

            var elapsed = DateTime.UtcNow - firstLogTime.Value;
            var timestamp = string.Format("{0:00}:{1:00}:{2:00}.{3:000}",
                (int)elapsed.TotalHours,
                elapsed.Minutes,
                elapsed.Seconds,
                elapsed.Milliseconds);

            Console.WriteLine($"[ChaseTheBug {timestamp}] {message}");
        }

        public void Tick() { }
        public void Quit() { }
        public byte Read(eAccess type, int address, out bool isValid) { isValid = false; return 0; }
        public void Reset() { }
    }
}
