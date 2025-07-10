# thanks Mathias ! (@IISResetMe)

function New-Gzip
{
	param(
		[Parameter(Mandatory = $true)]
		[ValidateScript({Test-Path $_ -PathType Leaf})]
		[string]$Path
	)

	if((Resolve-Path $Path).Provider.Name -ne 'FileSystem'){
		Write-Error "$Path is not a file..."
		return
	}

	$sourceItem = Get-Item $Path
	$targetName = $sourceItem.Name + '.gz'

	try{
		$sourceStream = $sourceItem.OpenRead()
		$targetStream = New-Object IO.FileStream $targetName ,'Create','Write','Read'
		$gzipStream   = [System.IO.Compression.GZipStream]::new($targetStream, [System.IO.Compression.CompressionMode]::Compress)
		$sourceStream.CopyTo($gzipStream)
	}
	catch{
		throw
	}
	finally{
		$gzipStream,$targetStream,$sourceStream |ForEach-Object {
			if($_){
				$_.Dispose()
			}
		}
	}

	return Get-Item $targetName
}

function ProcessTemplate
{
	param(
	[Parameter(Mandatory)]
	[string]$File = 'file.js',

	[switch]$PassThru
	)
	Write-Host "Processing " $File
	$js = Get-Item $File -ErrorAction SilentlyContinue
	if(-not $?){
		Write-Error "$File not found"
		return
	}

	$gz = Get-Item "${File}.gz" -ErrorAction SilentlyContinue

	if(-not $? -or $js.LastWriteTime -ge $gz.LastWriteTime){
		Write-Host "Creating " $File ".gz"
		$gz = New-Gzip -Path $js.FullName
	}

	if($PassThru){
		return $gz
	}
}

ProcessTemplate -File responsivetemplate.html
ProcessTemplate -File ReportBase.css
ProcessTemplate -File ReportBase.js
ProcessTemplate -File ReportCompromiseGraph.css
ProcessTemplate -File ReportHealthCheckConsolidation.css
ProcessTemplate -File ReportHealthCheckRules.css
ProcessTemplate -File ReportMapBuilder.css
ProcessTemplate -File ReportNetworkMap.css
ProcessTemplate -File ReportRiskControls.css
ProcessTemplate -File ReportMapBuilder.js
ProcessTemplate -File ReportNetworkMap.js
ProcessTemplate -File ReportCompromiseGraph.js
ProcessTemplate -File ReportCloudMain.js
ProcessTemplate -File fontawesome.all.min.css