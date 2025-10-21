import { DuckDBInstance } from '@duckdb/node-api';
import fs from 'fs'

const filePath = './data/telemetry/telemetry_data.parquet';
const instance = await DuckDBInstance.create(':memory:');
const connection = await instance.connect();
export { instance, connection };
// parse rows from CLI
const arg = process.argv[2];
const rowsToAdd = arg ? Number(arg) : 10;
if (!Number.isInteger(rowsToAdd) || rowsToAdd < 0) {
    console.error('Usage: node random_data_creator.js <number_of_rows> (non-negative integer)');
    process.exit(1);
}

await connection.run(`
    CREATE TABLE IF NOT EXISTS telemetry (
        id INTEGER,
        ts TIMESTAMP,
        voltage DOUBLE,
        current DOUBLE,
        temperature DOUBLE,
        status VARCHAR
    );
`);

const statuses = ['OK', 'WARN', 'ERROR'];

for (let i = 0; i < rowsToAdd; i++) {
    const id = i;
    const ts = new Date().toISOString();
    const voltage = +(Math.random() * 100).toFixed(3);
    const current = +(Math.random() * 50).toFixed(3);
    const temperature = +(Math.random() * 80 - 20).toFixed(2);
    const status = statuses[Math.floor(Math.random() * statuses.length)];

    await connection.run(
        `INSERT INTO telemetry (id, ts, voltage, current, temperature, status)
         VALUES (${id}, '${ts}', ${voltage}, ${current}, ${temperature}, '${status}');`
    );
}

await connection.run(`COPY telemetry TO '${filePath}' (FORMAT parquet);`)

console.log(`Inserted ${rowsToAdd} rows into telemetry`);
