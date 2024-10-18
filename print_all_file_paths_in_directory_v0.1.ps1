# Define the directory to search and the array of extensions
$directoryPath = "C:\\Users\\Neobyte\\Nextcloud\\Neurobyte\\2024 - 2025\\Semestre Inverno\SegInf\\Trabalho_1\\7. HybridFileEncryptor"
$extensions = @('*.txt', '*.pdf', '*.jpg', '*')  # Change this as needed

# Define the output file
$outputFile = "output_all_file_paths.txt"

# Clear the output file before writing to it
Clear-Content $outputFile

# Function to get all files recursively and filter by extensions
function Get-FilesByExtension {
    param (
        [string]$path,
        [array]$extArray
    )

    # Check if '*' is in the array, if so, list all files
    if ($extArray -contains '*') {
        Get-ChildItem -Path $path -Recurse -File | ForEach-Object {
            $_.FullName
        }
    } else {
        # Filter files by extensions in the array
        $files = @()
        foreach ($ext in $extArray) {
            $files += Get-ChildItem -Path $path -Recurse -File -Filter $ext | ForEach-Object {
                $_.FullName
            }
        }
        $files
    }
}

# Get the list of files
$filePaths = Get-FilesByExtension -path $directoryPath -extArray $extensions

# Write the file paths to the output file
$filePaths | Out-File -FilePath $outputFile -Encoding utf8

# Optional: Print a confirmation message
Write-Host "All file paths have been listed in $outputFile"
