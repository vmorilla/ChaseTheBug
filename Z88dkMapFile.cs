using System;
using System.CodeDom;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace ChaseTheBug
{
    public class Symbol
    {
        public string Name { get; }
        public int Address { get; }
        public string Segment { get; }
        public string Source { get; }

        public Symbol(string name, int address, string segment, string source = null)
        {
            Name = name;
            Address = address;
            Segment = segment;
            Source = source;
        }

        public override string ToString()
        {
            if (!string.IsNullOrEmpty(Source))
            {
                return $"{Name} @ 0x{Address:X6} [{Segment}] - {Source}";
            }
            return $"{Name} @ 0x{Address:X6} [{Segment}]";
        }
    }

    public class ResolvedAddress
    {
        public int LogicalAddress { get; private set; }
        public int PhysicalAddress { get; private set; }

        public Symbol Symbol { get; private set; }

        public int Offset { get; private set; }

        public ResolvedAddress(int logicalAddress, int physicalAddress, Symbol symbol = null, int offset = 0)
        {
            this.LogicalAddress = logicalAddress;
            this.PhysicalAddress = physicalAddress;
            this.Symbol = symbol;
            this.Offset = offset;
         }

        override public string ToString()
        {
            if (Symbol != null)
            {
                string output = $"{Symbol.Name}";
                if (Offset > 0)
                    output += $"+{Offset}";
                output += $" [{LogicalAddress:x}h / {PhysicalAddress:X}H @ {Symbol.Segment}]";
                return output;
            }
            else
            {
                return $"??? [{LogicalAddress:x}h / {PhysicalAddress:X}H]";
            }
        }
    }

    public class Z88dkMapFile
    {
        public List<Symbol> Symbols { get; private set; }
        private Dictionary<string, Symbol> symbolByName;
        private Dictionary<int, List<Symbol>> symbolsByAddress;

        private Z88dkMapFile()
        {
            Symbols = new List<Symbol>();
            symbolByName = new Dictionary<string, Symbol>();
            symbolsByAddress = new Dictionary<int, List<Symbol>>();
        }

        public static Z88dkMapFile Parse(string filePath)
        {
            var mapFile = new Z88dkMapFile();
            var nextMem = new NextMemResolver();
            
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"Map file not found: {filePath}");
            }

            // Regex pattern to match: symbol_name = $address ; addr, public, xxx , section, segment, source:line
            // Example: _frame_counter = $ADFA ; addr, public, xxx , ula_interrupt_asm, data_user, ula_interrupt.asm:28
            // __data_user_head                = $B27E ; const, public, def, , ,

            var regex = new Regex(@"^\s*([\S]*)\s*=\s*\$([0-9A-Fa-f]+)\s*;\s*[^,]*,\s*[^,]*,\s*[^,]*,\s*[^,]*,\s*(\w*)\s*,\s*(.*)$", RegexOptions.Compiled);

            foreach (var line in File.ReadLines(filePath))
            {
                var match = regex.Match(line);
                if (match.Success)
                {
                    string name = match.Groups[1].Value;
                    string addrStr = match.Groups[2].Value;
                    int address = addrStr.Length > 7 ? -1 : Convert.ToInt32(addrStr, 16);
                    string segment = match.Groups[3].Value.ToLower();
                    string source = match.Groups[4].Value.Trim();

                    var symbol = new Symbol(name, address, segment, source);
                    mapFile.Symbols.Add(symbol);
                    
                    // Index by name
                    mapFile.symbolByName[name] = symbol;
                    
                    // Index by address
                    if (!mapFile.symbolsByAddress.ContainsKey(address))
                    {
                        mapFile.symbolsByAddress[address] = new List<Symbol>();
                    }
                    mapFile.symbolsByAddress[address].Add(symbol);
                }
                else
                {
                    // Could not parse line
                    Console.WriteLine($"[Z88dkMapFile] Warning: Could not parse line: {line}");
                }
            }

            return mapFile;
        }

        public Symbol GetSymbolByName(string name)
        {
            return symbolByName.TryGetValue(name, out var symbol) ? symbol : null;
        }

        public List<Symbol> GetSymbolsByAddress(int address)
        {
            return symbolsByAddress.TryGetValue(address, out var symbols) ? symbols : new List<Symbol>();
        }

        public Symbol FindClosestSymbol(int address)
        {
            return Symbols
                .Where(s => s.Address <= address)
                .OrderByDescending(s => s.Address)
                .FirstOrDefault();
        }

        public ResolvedAddress LookupSymbol(int logicalAddress, NextMemResolver resolver)
        {
            int physicalAddress = resolver.GetPhysicalAddress(logicalAddress);
            // Try exact match first
            if (symbolsByAddress.TryGetValue(physicalAddress, out var symbols) && symbols.Count > 0)
            {
                return new ResolvedAddress(logicalAddress, physicalAddress, symbols[0]);
            }
            else
            {
                var closestSymbol = FindClosestSymbol(physicalAddress);
                if (closestSymbol != null && (physicalAddress >> 16 == closestSymbol.Address >> 16))
                {
                    return new ResolvedAddress(logicalAddress, physicalAddress, closestSymbol, physicalAddress - closestSymbol.Address);
                }

                return new ResolvedAddress(logicalAddress, physicalAddress);
                
            }
        }
    }

    public class NextMemResolver
    {
        private byte[] mmus = new byte[8] {255,255,10,11,4,5,0,1};

        public NextMemResolver() {}

        public int GetPhysicalAddress(int address)
        {
            byte address_mmu = (byte)((address >> 13) & 0x07);
            var segment = mmus[address_mmu];
            return (address & 0x1fff) + (segment << 16);
        }

        public void setMMU(byte mmu, byte value)
        {
            mmus[mmu] = value;
        }
    }
}