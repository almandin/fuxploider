<?php
//bypass changing mime type
if($_FILES['fileUpload']['type'] != "image/gif") {
echo "Sorry, we only allow uploading GIF images";
exit;
}
$uploaddir = './uploads/';
$uploadfile = $uploaddir . basename($_FILES['fileUpload']['name']);
if (move_uploaded_file($_FILES['fileUpload']['tmp_name'], $uploadfile)) {
echo "File is valid, and was successfully uploaded.\n";
} else {
echo "File uploading failed.\n";
}
?>
