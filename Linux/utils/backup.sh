#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: ./up.sh <file_or_folder>"
    exit 1
fi

TARGET=$1
UPLOAD_FILE=$TARGET
TEMP_CREATED=false

# 1. Handle Folders
if [ -d "$TARGET" ]; then
    echo "Compressing directory..."
    UPLOAD_FILE="${TARGET%/}.zip"
    zip -r "$UPLOAD_FILE" "$TARGET" > /dev/null
    TEMP_CREATED=true
fi

# 2. Upload to 0x0.st
echo "Uploading $UPLOAD_FILE to 0x0.st..."
LINK=$(curl -s -F "file=@$UPLOAD_FILE" https://0x0.st)

# 3. Cleanup
if [ "$TEMP_CREATED" = true ]; then
    rm "$UPLOAD_FILE"
fi

# 4. Output
if [[ "$LINK" == http* ]]; then
    echo -e "\nUpload Success!"
    echo "Download Link: $LINK"
else
    echo "Upload failed."
    echo "Response: $LINK"
fi
