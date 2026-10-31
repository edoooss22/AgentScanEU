using System.Text;

namespace AgentScan.Core;

internal static class JavaNames
{
    public const string EscapePrefix = "\\u";

    public static string DecodeModifiedUtf8(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder(b.Length);
        for (int i = 0; i < b.Length; i++)
        {
            byte c = b[i];
            int cp;
            if (c < 0x80) cp = c;
            else if ((c & 0xE0) == 0xC0 && i + 1 < b.Length)
            {
                cp = ((c & 0x1F) << 6) | (b[i + 1] & 0x3F);
                i += 1;
            }
            else if ((c & 0xF0) == 0xE0 && i + 2 < b.Length)
            {
                cp = ((c & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F);
                i += 2;
            }
            else cp = c;

            if (cp is >= 0x20 and < 0x7F) sb.Append((char)cp);
            else sb.Append(EscapePrefix).Append(cp.ToString("X4"));
        }
        return sb.ToString();
    }

    public static bool HasNonAscii(string decoded) =>
        decoded.Contains(EscapePrefix, StringComparison.Ordinal);

    public static bool LooksLikeFreedMemory(string decoded)
    {
        if (decoded.Contains("\\u0000", StringComparison.Ordinal)) return true;

        int high = 0, escapes = 0;
        int i = 0;
        while ((i = decoded.IndexOf(EscapePrefix, i, StringComparison.Ordinal)) >= 0)
        {
            if (i + 6 > decoded.Length) break;
            escapes++;
            if (int.TryParse(decoded.AsSpan(i + 2, 4),
                    System.Globalization.NumberStyles.HexNumber, null, out int cp) &&
                cp is >= 0x80 and <= 0xFF) high++;
            i += 6;
        }
        return escapes > 0 && high * 2 >= escapes;
    }

    public static string DescribeCodePoints(string decoded)
    {
        var kinds = new SortedSet<string>(StringComparer.Ordinal);
        int i = 0;
        while ((i = decoded.IndexOf(EscapePrefix, i, StringComparison.Ordinal)) >= 0)
        {
            if (i + 6 > decoded.Length) break;
            if (!int.TryParse(decoded.AsSpan(i + 2, 4),
                    System.Globalization.NumberStyles.HexNumber, null, out int cp)) { i += 2; continue; }
            kinds.Add(Classify(cp));
            i += 6;
        }
        return kinds.Count == 0 ? "" : string.Join(", ", kinds);
    }

    private static string Classify(int cp) => cp switch
    {
        < 0x20 => L("control character", "carácter de control"),
        0x7F => L("control character", "carácter de control"),
        >= 0x0080 and <= 0x00FF => L("Latin-1 (diacritics)", "Latín-1 (diacríticos)"),
        >= 0x0400 and <= 0x04FF => L("Cyrillic (Latin homoglyphs)", "cirílico (homoglifos latinos)"),
        >= 0x0370 and <= 0x03FF => L("Greek (Latin homoglyphs)", "griego (homoglifos latinos)"),
        >= 0x0590 and <= 0x08FF => L("right-to-left script", "escritura de derecha a izquierda"),
        0x200B or 0x200C or 0x200D or 0xFEFF => L("invisible zero-width character", "carácter invisible de ancho cero"),
        >= 0x200E and <= 0x200F => L("text direction mark", "marca de dirección del texto"),
        >= 0x2000 and <= 0x206F => L("typographic spaces and marks", "espacios y marcas tipográficas"),
        >= 0x2100 and <= 0x214F => L("letterlike symbols", "símbolos tipo letra"),
        >= 0x3000 and <= 0x303F => L("CJK punctuation", "puntuación CJK"),
        >= 0x4E00 and <= 0x9FFF => L("CJK ideographs", "ideogramas CJK"),
        >= 0xE000 and <= 0xF8FF => L("private use area", "área de uso privado"),
        >= 0xFF00 and <= 0xFFEF => L("fullwidth forms (ASCII homoglyphs)", "formas de ancho completo (homoglifos ASCII)"),
        _ => L($"other Unicode block (U+{cp:X4})", $"otro bloque Unicode (U+{cp:X4})"),
    };
}
