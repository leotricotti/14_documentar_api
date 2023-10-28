import { Router } from "express";
import { getAll, getOne } from "../controllers/products.controller.js";
import {
  saveProduct,
  deleteProduct,
  updateProduct,
} from "../controllers/realTimeProducts.controller.js";

//Inicializar servicios
const router = Router();

// Ruta que obtine todos los productos
router.get("/", getAll);

//Ruta para obtener un producto
router.get("/:id", getOne);

//Ruta para guardar un producto
router.post("/", saveProduct);

//Ruta para eliminar un producto
router.delete("/:id", deleteProduct);

//Ruta para actualizar un producto
router.put("/:id", updateProduct);

export default router;
