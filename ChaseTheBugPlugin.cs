using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.Remoting.Channels;
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

    public class ChaseTheBugPlugin : iPlugin
    {
        private iCSpect cspect;

        private NextMemResolver nextMem = new NextMemResolver();

        private Z88dkMapFile symbolMap;

        private bool startWatching = false;

        private bool disabled = false;

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

            for (ushort address = 0x000; address < 0x4000; address++)
            {
                sIOs.Add(new sIO(address, eAccess.Memory_Write));
            }

            var dataUserHead = symbolMap.GetSymbolByName("__data_crt_head");
            if (dataUserHead != null)
            {
                Log($"Data head at 0x{dataUserHead.Address:X4}");
                for (ushort address = 0x8000; address < dataUserHead.Address; address++)
                {
                    sIOs.Add(new sIO(address, eAccess.Memory_Write));
                }
            }
            else
            {
                Log("Warning: __data_user_head symbol not found in map file. Skipping upper memory watch setup.");
            }

            // Add key press 
            sIOs.Add(new sIO("<ctrl>g", eAccess.KeyPress, 0));
            sIOs.Add(new sIO("<ctrl>h", eAccess.KeyPress, 1));

            return sIOs;
        }


        public void OSTick()
        {
        }

        public bool Write(eAccess type, int port, int id, byte mmu1)
        {
            if (!startWatching)
                return false;
            // Attempt to write in read-only memory
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
                Log($"Attempted write to 0x{port:X4} from address 0x{pc:X4}");
                cspect.Debugger(eDebugCommand.Enter);
            }

            return false;
        }

        public byte Read(eAccess type, int port, int _id, out bool isvalid)
        {
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

            foreach (var line in System.IO.File.ReadLines(configPath))
            {
                if (line.StartsWith("MapFile="))
                {
                    var mapFile = line.Substring("MapFile=".Length);
                    Log("Loading map file: " + mapFile);
                    symbolMap = Z88dkMapFile.Parse(mapFile);
                    Log($"Loaded {symbolMap.Symbols.Count} symbols from map file.");
                }

                if (line.StartsWith("Disabled"))
                {
                    disabled = true;
                    return;
                }
            }
        }


        private static int ParseIntWithHexSupport(string input)
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

            return -1;
        }

        private void Log(string message)
        {
            Console.WriteLine("[ChaseTheBug] " + message);
        }

        public void Tick() { }
        public void Quit() { }
        public byte Read(eAccess type, int address, out bool isValid) { isValid = false; return 0; }
        public void Reset() { }
    }
}
