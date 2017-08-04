<?php
//bypass not needed, zero check done
$target_path="./uploads/";
//Here we set the target path that will save the file in to.
$target_path = $target_path.basename($_FILES['uploadedfile']['name']);
// here wll move the desired file from the tmp directory to the target path
if(move_uploaded_file($_FILES['fileUpload']['tmp_name'],$target_path.$_FILES['fileUpload']['name'])){
echo "the file " . basename($_FILES['uploadedfile']['name']) . " has been uploaded! ";
}else {
echo "there was an error uploading the file ,please try again!";
}
?>
