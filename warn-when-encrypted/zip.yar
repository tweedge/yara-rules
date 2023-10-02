rule Warn_When_Encrypted_ZIP
{
    meta:
        author = "tweedge"
        description = "Detects encrypted ZIP files. This means few or no security vendors will scan this file, because they can't read what's in it! Make sure you trust this file."
        date = "2023-10-02"

    strings:
        $zip_header = { 50 4b 03 04 }
        $empty_zip_header = { 50 4b 05 06 }
        $spanned_zip_header = { 50 4b 07 08 }

    condition:
        // check that one of the ZIP headers is in the magic number position
        // thanks to: https://github.com/Kamrion/yara.magic
        (
            $zip_header at 0 or
            $empty_zip_header at 0 or
            $spanned_zip_header at 0
        ) and

        // iterate over ZIP headers in the file
        for any i in (1..#zip_header):
        (
            // then see if the encrypt bits are set in each header
            uint16(@zip_header[i]+6) & 0x1 == 0x1
        )
}