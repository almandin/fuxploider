<?php
//bypass using uppercase extensions (PHP)
$blacklist = array(".php","html","shtml",".phtml", ".php3", ".php4");
foreach ($blacklist as $item) {
if(preg_match("/$item\$/", $_FILES['fileUpload']['name'])) {
echo "We do not allow uploading PHP files\n";
exit;
}
}
$uploaddir = './uploads/';
$uploadfile = $uploaddir . basename($_FILES['fileUpload']['name']);
if (move_uploaded_file($_FILES['fileUpload']['tmp_name'], $uploadfile)) {
echo "File is valid, and was successfully uploaded.\n";
} else {
echo "File uploading failed.\n";
}
?>
