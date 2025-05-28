use actix_cors::Cors;
use actix_web::http::StatusCode;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use log::{debug, error, info, warn};
use rand::{thread_rng, Rng};
use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

// Request and response structs
#[derive(Deserialize)]
struct HexStringRequest {
    hex_string: String,
}

#[derive(Serialize)]
struct ApiKeyResponse {
    api_key: String,
}

#[derive(Deserialize)]
struct ReverseLookupRequest {
    api_key: String,
}

#[derive(Serialize)]
struct HexStringResponse {
    hex_string: String,
}

// Error handling
#[derive(thiserror::Error, Debug)]
enum AppError {
    #[error("Database error: {0}")]
    DbError(#[from] rusqlite::Error),

    #[error("Hex string not found")]
    NotFound,

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl actix_web::ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::DbError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> HttpResponse {
        // Log the error
        match self {
            AppError::DbError(e) => error!("Database error: {}", e),
            AppError::NotFound => warn!("Resource not found"),
            AppError::InternalError(e) => error!("Internal server error: {}", e),
            AppError::InvalidInput(e) => warn!("Invalid input: {}", e),
        }
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "error": self.to_string()
        }))
    }
}

// Database struct that will be shared across handlers
struct AppState {
    db: Mutex<Connection>,
}

// Initialize the SQLite database
fn init_db(conn: &Connection) -> SqliteResult<()> {
    debug!("Creating API keys table if it doesn't exist");

    match conn.execute(
        "CREATE TABLE IF NOT EXISTS api_keys (
            hex_string TEXT PRIMARY KEY,
            api_key TEXT NOT NULL
        )",
        params![],
    ) {
        Ok(_) => {
            debug!("API keys table created or already exists");
            Ok(())
        }
        Err(e) => {
            error!("Failed to create API keys table: {}", e);
            Err(e)
        }
    }
}

// Helper function to generate API key
fn generate_api_key() -> String {
    debug!("Generating new API key");
    let api_key_prefix = "sk_";
    let random_bytes: Vec<u8> = (0..24).map(|_| thread_rng().r#gen::<u8>()).collect();
    let encoded = general_purpose::URL_SAFE.encode(&random_bytes);
    let api_key = format!("{}{}", api_key_prefix, encoded);
    debug!("API key generated successfully");
    api_key
}

// Helper function to validate a hex string with 0x prefix
fn is_valid_hex_format(hex_string: &str) -> bool {
    debug!("Validating hex string format: {}", hex_string);

    // Check if string starts with "0x" prefix
    if !hex_string.starts_with("0x") {
        debug!("Hex string validation failed: missing 0x prefix");
        return false;
    }

    // Check if the remaining characters (after 0x) are valid hex
    let is_valid = hex_string[2..].chars().all(|c| c.is_ascii_hexdigit());
    if !is_valid {
        debug!("Hex string validation failed: contains non-hexadecimal characters");
    } else {
        debug!("Hex string validation passed");
    }

    is_valid
}

// Handler functions
async fn create_api_key(
    data: web::Json<HexStringRequest>,
    app_state: web::Data<Arc<AppState>>,
) -> Result<impl Responder, AppError> {
    let hex_string = &data.hex_string;
    info!(
        "Received request to create API key for hex string: {}",
        hex_string
    );

    // Validate the hex string format
    if !is_valid_hex_format(hex_string) {
        warn!("Invalid hex string format received: {}", hex_string);
        return Err(AppError::InvalidInput(
            "Invalid hex string format. Expected format: 0xHEXSTRING".to_string(),
        ));
    }
    debug!("Hex string validation passed for: {}", hex_string);

    let api_key = generate_api_key();
    debug!("Generated new API key for hex string: {}", hex_string);

    // Insert or replace in database
    let db = match app_state.db.lock() {
        Ok(db) => db,
        Err(e) => {
            error!("Failed to acquire database lock: {}", e);
            return Err(AppError::InternalError("Database lock error".to_string()));
        }
    };

    match db.execute(
        "INSERT OR REPLACE INTO api_keys (hex_string, api_key) VALUES (?, ?)",
        params![hex_string, &api_key],
    ) {
        Ok(_) => debug!(
            "Successfully stored API key in database for: {}",
            hex_string
        ),
        Err(e) => {
            error!("Database error while storing API key: {}", e);
            return Err(AppError::DbError(e));
        }
    }

    info!(
        "Successfully created API key for hex string: {}",
        hex_string
    );
    Ok(HttpResponse::Ok().json(ApiKeyResponse { api_key }))
}

async fn get_api_key(
    query: web::Query<HexStringRequest>,
    app_state: web::Data<Arc<AppState>>,
) -> Result<impl Responder, AppError> {
    let hex_string = &query.hex_string;
    info!(
        "Received request to get API key for hex string: {}",
        hex_string
    );

    // Validate the hex string format
    if !is_valid_hex_format(hex_string) {
        warn!("Invalid hex string format received: {}", hex_string);
        return Err(AppError::InvalidInput(
            "Invalid hex string format. Expected format: 0xHEXSTRING".to_string(),
        ));
    }
    debug!("Hex string validation passed for: {}", hex_string);

    // Get from database
    let db = match app_state.db.lock() {
        Ok(db) => db,
        Err(e) => {
            error!("Failed to acquire database lock: {}", e);
            return Err(AppError::InternalError("Database lock error".to_string()));
        }
    };
    let api_key: String = db
        .query_row(
            "SELECT api_key FROM api_keys WHERE hex_string = ?",
            params![hex_string],
            |row| row.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                warn!("No API key found for hex string: {}", hex_string);
                AppError::NotFound
            }
            other => {
                error!("Database error while retrieving API key: {}", other);
                AppError::DbError(other)
            }
        })?;
    info!(
        "Successfully retrieved API key for hex string: {}",
        hex_string
    );
    Ok(HttpResponse::Ok().json(ApiKeyResponse { api_key }))
}

async fn rotate_api_key(
    data: web::Json<HexStringRequest>,
    app_state: web::Data<Arc<AppState>>,
) -> Result<impl Responder, AppError> {
    let hex_string = &data.hex_string;
    info!(
        "Received request to rotate API key for hex string: {}",
        hex_string
    );

    // Validate the hex string format
    if !is_valid_hex_format(hex_string) {
        warn!("Invalid hex string format received: {}", hex_string);
        return Err(AppError::InvalidInput(
            "Invalid hex string format. Expected format: 0xHEXSTRING".to_string(),
        ));
    }
    debug!("Hex string validation passed for: {}", hex_string);

    // Check if hex string exists
    let db = match app_state.db.lock() {
        Ok(db) => db,
        Err(e) => {
            error!("Failed to acquire database lock: {}", e);
            return Err(AppError::InternalError("Database lock error".to_string()));
        }
    };

    let exists: bool = match db.query_row(
        "SELECT 1 FROM api_keys WHERE hex_string = ?",
        params![hex_string],
        |_| Ok(true),
    ) {
        Ok(_) => true,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            warn!("No existing API key found for rotation: {}", hex_string);
            false
        }
        Err(e) => {
            error!("Database error while checking if hex string exists: {}", e);
            return Err(AppError::DbError(e));
        }
    };

    if !exists {
        return Err(AppError::NotFound);
    }

    // Generate new API key
    let new_api_key = generate_api_key();
    debug!("Generated new API key for rotation: {}", hex_string);

    // Update in database
    match db.execute(
        "UPDATE api_keys SET api_key = ? WHERE hex_string = ?",
        params![&new_api_key, hex_string],
    ) {
        Ok(_) => debug!(
            "Successfully updated API key in database for: {}",
            hex_string
        ),
        Err(e) => {
            error!("Database error while updating API key: {}", e);
            return Err(AppError::DbError(e));
        }
    }

    info!(
        "Successfully rotated API key for hex string: {}",
        hex_string
    );
    Ok(HttpResponse::Ok().json(ApiKeyResponse {
        api_key: new_api_key,
    }))
}

async fn reverse_lookup_hex(
    data: web::Json<ReverseLookupRequest>,
    app_state: web::Data<Arc<AppState>>,
) -> Result<impl Responder, AppError> {
    let api_key = &data.api_key;
    info!("Received request to reverse lookup hex string from API key");

    let db = app_state.db.lock().map_err(|e| {
        error!("Failed to acquire DB lock: {}", e);
        AppError::InternalError("Database lock error".into())
    })?;
    let hex_string: String = db
        .query_row(
            "SELECT hex_string FROM api_keys WHERE api_key = ?",
            params![api_key],
            |row| row.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => AppError::NotFound,
            other => AppError::DbError(other),
        })?;

    Ok(HttpResponse::Ok().json(HexStringResponse { hex_string }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    info!("Starting API Key Server");

    // Initialize database
    let conn = Connection::open("apikeys.db").expect("Failed to open database");
    init_db(&conn).expect("Failed to initialize database");

    let app_state = Arc::new(AppState {
        db: Mutex::new(conn),
    });

    // Start HTTP server
    HttpServer::new(move || {
        // Configure CORS middleware
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(app_state.clone()))
            .route("/gen-api-key", web::post().to(create_api_key))
            .route("/get-api-key", web::get().to(get_api_key))
            .route("/rotate-api-key", web::post().to(rotate_api_key))
            .route("/reverse-lookup", web::post().to(reverse_lookup_hex))
    })
    .bind("127.0.0.1:8081")? // Change to match the port in your error message
    .run()
    .await
}
