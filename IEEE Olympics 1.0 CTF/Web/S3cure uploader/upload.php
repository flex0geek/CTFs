<?php
if(isset($_GET["upload"])) {
  $target_dir= "uploads/";
  $vars = explode(".", $_FILES["FileToUpload"]["name"]);
  $filename=$vars[0];
  $ext = $vars[1];

  //randomizing file name
  $time = date('Y-m-d H:i:s');
  $new_name = md5(rand(1,1000).$time.$filename."0x4148fo").".".strtolower(pathinfo(basename($_FILES["FileToUpload"]["name"]),PATHINFO_EXTENSION));
  $filename=explode(".", $_FILES["FileToUpload"]["name"])[0];
  $ext = $filename = explode(".", $_FILES["FileToUpload"]["name"])[1];
  $target_file = $target_dir . "$new_name";

  // Check if file already exists
  if (file_exists($target_file)) {
    echo "File already exists.";
    $uploadOk = 0;
    die();
  }

  // Check file size
  if ($_FILES["FileToUpload"]["size"] > 500000) {
    echo "File is too large.";
    $uploadOk = 0;
    die();
  }

  $uploadOk = 1;
  $check = getimagesize($_FILES["FileToUpload"]["tmp_name"]);
  if($check !== false) {
      $uploadOk = 1;
  } else {
    echo "File is not an image.";
    $uploadOk = 0;
    die();
  }
}
move_uploaded_file($_FILES["FileToUpload"]["tmp_name"], $target_file);
if( strtolower(pathinfo(basename($_FILES["FileToUpload"]["name"]),PATHINFO_EXTENSION)) =="jpg" ){
  echo "File uploaded successfully to $target_file";
}
else{
	die("Invalid file type");
}
?>