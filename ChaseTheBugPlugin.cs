using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq.Expressions;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
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
        private bool startWatching = false;
        private bool working = false;
        private List<ushort> watchWriteAddresses = new List<ushort>();
        private TraceRange tracingRange = new TraceRange(0x2F6E, 0x2FD5);
        private iCSpect cspect;


        public List<sIO> Init(iCSpect c)
        {
            cspect = c;
            var sIOs = new List<sIO>();
            LoadConfig();
            foreach (var address in watchWriteAddresses)
            {
                sIOs.Add(new sIO(address, eAccess.Memory_Write));
                Log($"Watching writes to address 0x{address:X4}");
            }

            sIOs.Add(new sIO(tracingRange.TraceStart, eAccess.Memory_EXE, 0));

            // Add key press 
            sIOs.Add(new sIO("<ctrl>g", eAccess.KeyPress, 0));
            sIOs.Add(new sIO("<ctrl>h", eAccess.KeyPress, 1));

            return sIOs;
        }


        public void OSTick()
        {
        }

        public bool Write(eAccess type, int port, int id, byte value)
        {
            if (watchWriteAddresses.Contains((ushort)port) && type == eAccess.Memory_Write && startWatching)
            {
                cspect.ReadWord((ushort)port);
                Log($"Memory write attempt to 0x{port:x}... Halting");
                cspect.Debugger(eDebugCommand.Enter);
                return true;
            }

            return false;
        }


        public byte Read(eAccess type, int port, int _id, out bool isvalid)
        {

            // Avoids reentrant calls
            if (!working)
            {
                working = true;

                Log($"Read 0x{port:x}, {type}");
                Log("=========================================================");
                cspect.Debugger(eDebugCommand.Enter);

                List<ushort> callStack = new List<ushort>();
                ushort prev_pc, prev_sp, prevInstructionSize = 0;
                var regs = cspect.GetRegs();
                do
                {
                    prev_pc = regs.PC;
                    prev_sp = regs.SP;
                    regs = cspect.GetRegs();
                    var instr = cspect.DissasembleMemory(regs.PC, false);


                    var pc_jump = regs.PC - prev_pc;

                    if (regs.SP == prev_sp - 2) {
                        if (cspect.ReadWord(regs.SP) == prev_pc + prevInstructionSize && !(pc_jump <=4 && pc_jump > 0)) {
                            callStack.Add((ushort)(prev_pc + prevInstructionSize));
                        }
                    } else if (regs.SP == prev_sp + 2 && cspect.ReadWord(prev_sp) == regs.PC && callStack.Count > 0) {
                        callStack.RemoveAt(callStack.Count - 1);
                    }

                    ushort stackReference = 0xFF3E;
                    var stackReferenceValue = cspect.ReadWord(stackReference);
                    string tabs = new string('\t', callStack.Count);
                    Console.WriteLine($"{tabs}{regs.PC:X} - [0x{stackReference:x}] = 0x{stackReferenceValue:x} | SP = 0x{regs.SP:x} | HL = 0x{regs.HL:x} | DE = 0x{regs.DE:x} | BC = 0x{regs.BC:x} | AF = 0x{regs.AF:x} ; {instr.line}");
                    
                    if (regs.PC == 0x2fce && regs.HL != 0xb6ff && regs.HL != 0xB6EB) {
                        // Stop here
                        Console.WriteLine("!!!!!!!!!!!!!!!!!!!Memory corruption!!!!!!!!!");
                        isvalid = false;
                        return 0;
                    }
                    
                    prevInstructionSize = (ushort)instr.bytes;
                    cspect.Debugger(eDebugCommand.Step);                    
                } while (regs.PC != tracingRange.TraceEnd);

                Log("=======================================================");
                cspect.Debugger(eDebugCommand.Run);
                working = false;
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

            foreach (var line in System.IO.File.ReadLines(configPath))
            {
                if (line.StartsWith("WatchAddress="))
                {
                    var numberStrs = line.Substring("WatchAddress=".Length).Split(',');

                    // Parse the numbers based on their format
                    ushort address = (ushort)ParseIntWithHexSupport(numberStrs[0]);
                    int length = numberStrs.Length > 1 ? ParseIntWithHexSupport(numberStrs[1]) : 1;

                    Log($"Loaded config: WatchAddress={address:X},{length}");

                    for (ushort i = 0; i < length; i++)
                    {
                        watchWriteAddresses.Add((ushort)(address + i));
                    }
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
            Console.WriteLine("[PortLogger] " + message);
        }

        public void Tick() { }
        public void Quit() { }
        public byte Read(eAccess type, int address, out bool isValid) { isValid = false; return 0; }
        public void Reset() { }
    }
}
