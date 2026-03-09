using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using static PKHeX.Core.Injection.LiveHeXVersion;

namespace PKHeX.Core.Injection;

public sealed class LPFRLG : InjectionBase
{
    public static ReadOnlySpan<LiveHeXVersion> SupportedVersions => [ FRLG_D_v100, FRLG_E_v100, FRLG_F_v100, FRLG_I_v100, FRLG_J_v100, FRLG_S_v100];
    private const uint fakeHeap = 0x2020000;
    private const uint startingOffset = 0x1208000;
    public static uint securitykey = 0;
    public static uint GetB1S1Offset(LiveHeXVersion lv) => lv switch 
    { 
        LiveHeXVersion.FRLG_E_v100 => 0xBD68D2E0,
        LiveHeXVersion.FRLG_I_v100 => 0xBD68D230,
        LiveHeXVersion.FRLG_D_v100 => 0xBD68D230,
        LiveHeXVersion.FRLG_S_v100 => 0xBD68D230,
        LiveHeXVersion.FRLG_F_v100 => 0xBD68D230,
        LiveHeXVersion.FRLG_J_v100 => 0xBD68D240,
    };
    public uint GetLargeBlockOffset(LiveHeXVersion lv) => lv switch
    {
        LiveHeXVersion.FRLG_E_v100 => 0xBD68D2D8,
        LiveHeXVersion.FRLG_I_v100 => 0xBD68D228,
        LiveHeXVersion.FRLG_D_v100 => 0xBD68D228,
        LiveHeXVersion.FRLG_S_v100 => 0xBD68D228,
        LiveHeXVersion.FRLG_F_v100 => 0xBD68D228,
        LiveHeXVersion.FRLG_J_v100 => 0xBD68D238,
    };
    public uint GetSmallBlockOffset(LiveHeXVersion lv) => lv switch
    {
        LiveHeXVersion.FRLG_E_v100 => 0xBD68D2DC,
        LiveHeXVersion.FRLG_I_v100 => 0xBD68D22C,
        LiveHeXVersion.FRLG_D_v100 => 0xBD68D22C,
        LiveHeXVersion.FRLG_S_v100 => 0xBD68D22C,
        LiveHeXVersion.FRLG_F_v100 => 0xBD68D22C,
        LiveHeXVersion.FRLG_J_v100 => 0xBD68D23C,
        _ => 0,
    };
    public override Span<byte> ReadBox(PokeSysBotMini psb, int box, int len, List<byte[]> allpkm)
    {
        var lv = psb.Version;
        var boxoffbytes = psb.com.ReadBytes(GetB1S1Offset(lv), 4);
        var boxoff = BitConverter.ToUInt32(boxoffbytes);
        boxoff -= fakeHeap;
        boxoff += startingOffset;
        var boxsize = RamOffsets.GetSlotCount(lv) * RamOffsets.GetSlotSize(lv);
        var boxstart = boxoff + (ulong)(box * boxsize);
        return psb.com.ReadBytes(boxstart + 4, boxsize);
    }
    public override Span<byte> ReadSlot(PokeSysBotMini psb, int box, int slot)
    {
        var lv = psb.Version;
        var slotsize = RamOffsets.GetSlotSize(lv);
        var boxoffbytes = psb.com.ReadBytes(GetB1S1Offset(lv), 4);
        var boxoff = BitConverter.ToUInt32(boxoffbytes);
        boxoff -= fakeHeap;
        boxoff += startingOffset;
        var slotstart = boxoff + (ulong)(slot * slotsize);
        return psb.com.ReadBytes(slotstart + 4, slotsize);
    }
    public override void SendSlot(PokeSysBotMini psb, ReadOnlySpan<byte> data, int box, int slot)
    {
        var lv = psb.Version;
        var slotsize = RamOffsets.GetSlotSize(lv);
        var boxoffbytes = psb.com.ReadBytes(GetB1S1Offset(lv), 4);
        var boxoff = BitConverter.ToUInt32(boxoffbytes);
        boxoff -= fakeHeap;
        boxoff += startingOffset;
        var slotstart = boxoff + (ulong)(slot * slotsize);
        psb.com.WriteBytes(data, slotstart + 4);
    }
    public override void SendBox(PokeSysBotMini psb, ReadOnlySpan<byte> boxData, int box)
    {
        var lv = psb.Version;
        var boxoffbytes = psb.com.ReadBytes(GetB1S1Offset(lv), 4);
        var boxoff = BitConverter.ToUInt32(boxoffbytes);
        boxoff -= fakeHeap;
        boxoff += startingOffset;
        var boxsize = RamOffsets.GetSlotCount(lv) * RamOffsets.GetSlotSize(lv);
        var boxstart = boxoff + (ulong)(box * boxsize);
        psb.com.WriteBytes(boxData, boxstart + 4);
    }
    public override bool ReadBlockFromString(PokeSysBotMini psb, SaveFile sav, string block, out List<byte[]>? read)
    {
        read = null;
        try
        {
            var offsets = SCBlocks[psb.Version].Where(z => z.Display == (block == "Large" ? "Items" : block)).First();
            var props = sav.GetType().GetProperty(block) ?? throw new Exception($"{block} not found");
            var blockoffbytes = offsets.Name == "Large" ? psb.com.ReadBytes(GetLargeBlockOffset(psb.Version), 4) : psb.com.ReadBytes(GetSmallBlockOffset(psb.Version), 4);
            var blockoff = BitConverter.ToUInt32(blockoffbytes);
            blockoff -= fakeHeap;
            blockoff += startingOffset;
            blockoff += (uint)offsets.Offset;
            var size = offsets.Name == "Large" ? 0x3e00 : Marshal.SizeOf(props.PropertyType);
            var ram = psb.com.ReadBytes(blockoff, size);
            var val = ConvertValue(props, ram);
            if (offsets.IsSecured)
                val = (uint)val ^ ((SAV3FRLG)sav).SecurityKey;
            if (offsets.Display == "Large")
                ram.CopyTo(((SAV3)sav).Large);
            else
                props.SetValue(sav, val);
            read = [ram.ToArray()];
            return true;
        }
        catch (Exception e)
        {
            Debug.WriteLine(e.StackTrace);
            return false;
        }
    }
    public override void WriteBlocksFromSAV(PokeSysBotMini psb, string block, SaveFile sav)
    {
        var props = sav.GetType().GetProperty(block) ?? throw new Exception($"{block} not found");
        var offsets = SCBlocks[psb.Version].Where(z => z.Display == (block == "Large" ? "Items" : block)).First();
        var data = block == "Large" ? ((SAV3)sav).Large.ToArray() : props.GetValue(sav);
        if (offsets.IsSecured)
            data = (uint)data ^ ((SAV3FRLG)sav).SecurityKey;
        var blockoffbytes = offsets.Name == "Large" ? psb.com.ReadBytes(GetLargeBlockOffset(psb.Version), 4) : psb.com.ReadBytes(GetSmallBlockOffset(psb.Version), 4);
        var blockoff = BitConverter.ToUInt32(blockoffbytes);
        blockoff -= fakeHeap;
        blockoff += startingOffset;
        blockoff += (uint)offsets.Offset;
        psb.com.WriteBytes(block == "Large" ? (byte[])data : BitConverter.GetBytes((uint)data), blockoff);
    }
    public object ConvertValue(PropertyInfo info, Span<byte> bytes)
    {
        var t = info.PropertyType;
        if (t == typeof(UInt16))
            return BitConverter.ToUInt16(bytes);
        else if (t == typeof(UInt32))
            return BitConverter.ToUInt32(bytes);
        else if (t == typeof(UInt64))
            return BitConverter.ToUInt64(bytes);
        else if (t == typeof(UInt128))
            return BitConverter.ToUInt128(bytes);
        else
            return bytes.ToArray();
        throw new InvalidEnumArgumentException($"Unsupported type {t} for {info.Name}");
    }
    private static BlockData Get(uint offset, string name, string display, SCTypeCode type) => new()
    {
        Name = name,
        Display = display,
        Type = type,
        Offset = offset,
    };
    private static BlockData Get(uint offset, string name, string display, bool secured) => new()
    {
        Name = name,
        Display = display,
        Offset = offset,
        IsSecured = secured,
    };
    private static BlockData Get(uint offset, string name, string display) => new()
    {
        Name = name,
        Display = display,
        Offset = offset,
    };
    public static readonly BlockData[] Blocks_FRLG = new[]
    {
        Get(0x290, "Large", "Money", true),
        Get(0x294, "Large", "Coin", true),
        Get(0, "Large", "Items"),
        Get(0xF20, "Small", "SecurityKey")
    };
    public static readonly Dictionary<LiveHeXVersion, BlockData[]> SCBlocks = new()
    {
        { FRLG_E_v100, Blocks_FRLG  },
        { FRLG_I_v100, Blocks_FRLG },
    };
    public override Dictionary<string, string> SpecialBlocks { get; } = new()
    {
        { "Large", "B_OpenItemPouch_Click" },
    };
}

