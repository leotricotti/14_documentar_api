async function getDocumentation() {
  const token = localStorage.getItem("token");
  console.log(token);
  const response = await fetch("http://localhost:8080/apidocs", {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  });
  if (response.status === 200) {
    window.location.href = response.url;
  } else if (response.status === 401) {
    Swal.fire({
      icon: "error",
      title: "Oops...",
      text: "No se pudo autenticar al usuario",
      confirmButtonText: "Aceptar",
      showClass: {
        popup: "animate__animated animate__zoomIn",
      },
      hideClass: {
        popup: "animate__animated animate__zoomOut",
      },
    });
  } else {
    Swal.fire({
      icon: "error",
      title: "Oops...",
      text: "No se pudo obtener la documentación",
      confirmButtonText: "Aceptar",
      showClass: {
        popup: "animate__animated animate__zoomIn",
      },
      hideClass: {
        popup: "animate__animated animate__zoomOut",
      },
    });
  }
}
