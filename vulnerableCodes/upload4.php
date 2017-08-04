<?php
//bypass with php code in jpeg or gif comment
$imageinfo = getimagesize($_FILES['fileUpload']['tmp_name']);
if($imageinfo['mime'] != 'image/gif' && $imageinfo['mime'] != 'image/jpeg') {
echo "Sorry, we only accept GIF and JPEG images\n";
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
