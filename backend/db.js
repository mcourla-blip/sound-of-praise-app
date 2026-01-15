import fs from "fs";
import path from "path";

const DB_PATH = path.join(process.cwd(), "data.json");

const defaultDb = {
  users: [],
  events: [],
  attendance: [],
  payments: [],
  messages: [],
  publicContent: {
    about: "Sound Of Praise — Gospel, culture et inclusion.",
    portfolioPdfUrl: ""
  }
};

export function uid(prefix="id"){
  return `${prefix}_${Math.random().toString(16).slice(2)}${Date.now().toString(16)}`;
}

export function loadDb(){
  if(!fs.existsSync(DB_PATH)){
    fs.writeFileSync(DB_PATH, JSON.stringify(defaultDb, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
}

export function saveDb(db){
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}
