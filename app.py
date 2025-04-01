import sqlite3
from flask import Flask, render_template, request, g, jsonify
from flask_socketio import SocketIO, emit
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import os
import json

# --- Configuration ---
DATABASE = 'tracker.db'
LOG_FILE = 'log.txt' # Log file name as requested
VEHICLE_INFO = "Scooter TVS Ntorq 125 Race Edition (KL 47M 4634)"
# !!! IMPORTANT: Use a fixed, strong secret key for production deployments !!!
# Example: Set as an environment variable: export SECRET_KEY='your_strong_random_key'
SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24).hex()) # Random for dev if not set

# --- Define Locations ---
# Locations corresponding to the buttons in admin.html
LOCATIONS = [
    "Home", "Puthanpally", "Methalapadam", "Methala", "Anjappalam",
    "NH 66 Bypass", "Cheraman Masjid", "Keetholi", "Anapuzha",
    "Anjangadi Bus Stop", "Krishnankotta", "Poyya beverage",
    "Poyya junction", "Company Kunnu", "Chenthuruthy bridge",
    "Chenthuruthy junction", "Malapallipuram", "Pallippuram",
    "Post Office Bus Stop", "HOLY GRACE"
]
# All possible valid values for the 'current_location' field in the database
VALID_LOCATION_STATES = LOCATIONS + ["Not Started Yet", "Journey Ended"] # Added Journey Ended state


# --- Logging Setup ---
def setup_logging():
    # Define log format
    log_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)-5.5s] [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    log_level = logging.INFO # Set desired log level (INFO, DEBUG, WARNING, ERROR)

    # --- Console Handler ---
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(log_level)

    # --- File Handler (logs to log.txt) ---
    # Rotate logs: 10MB max size, keep 5 backup files
    try:
        file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(log_level)
    except Exception as e:
        print(f"!!! WARNING: Could not setup file logging to {LOG_FILE}: {e}")
        file_handler = None # Disable file logging if setup fails

    # Get root logger and attach handlers
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(console_handler)
    if file_handler:
        root_logger.addHandler(file_handler)
        print(f"--- Logging configured to console and file: {os.path.abspath(LOG_FILE)} ---")
    else:
         print(f"--- Logging configured to console only ---")


    # Silence overly verbose libraries
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('engineio').setLevel(logging.WARNING)
    logging.getLogger('socketio').setLevel(logging.WARNING)

    # Return a specific logger for our application code
    app_specific_logger = logging.getLogger('TrackerApp')
    app_specific_logger.setLevel(log_level) # Use the same level or customize
    return app_specific_logger

app_logger = setup_logging()


# --- Flask App and SocketIO Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
# Silence Flask's built-in logger if using our custom setup
# app.logger.disabled = True

# Choose async mode for production (install required library: pip install eventlet / gevent)
# import eventlet
# eventlet.monkey_patch()
# socketio = SocketIO(app, async_mode='eventlet', logger=False, engineio_logger=False)
# OR
# from gevent import monkey
# monkey.patch_all()
# socketio = SocketIO(app, async_mode='gevent', logger=False, engineio_logger=False)

# Development mode:
socketio = SocketIO(app, logger=False, engineio_logger=False) # Use our loggers


# --- Database Functions ---

def get_db():
    """Opens a new database connection if there is none yet for the current request context."""
    if 'db' not in g:
        try:
            g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES, timeout=10)
            g.db.execute("PRAGMA journal_mode=WAL;") # Write-Ahead Logging for better concurrency
            g.db.row_factory = sqlite3.Row
            app_logger.debug("Database connection opened.")
        except sqlite3.Error as e:
            app_logger.critical(f"CRITICAL: Failed to connect to database {DATABASE}: {e}", exc_info=True)
            raise ConnectionError(f"Failed to connect to database: {e}")
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        try:
            db.close()
            app_logger.debug("Database connection closed.")
        except sqlite3.Error as e:
             app_logger.error(f"Error closing database connection: {e}", exc_info=True)
    if error:
         app_logger.error(f"App context teardown encountered an error: {error}", exc_info=True)

def init_db(force_reset=False):
    """Initializes the database schema using 'with' for connection management."""
    if force_reset and os.path.exists(DATABASE):
        app_logger.warning("Forcibly removing existing database due to force_reset=True.")
        try:
            os.remove(DATABASE)
        except OSError as e:
            app_logger.error(f"Error removing database file {DATABASE}: {e}")
            raise # Stop if DB cannot be removed when forced

    # Use 'with' for automatic transaction handling (commit/rollback) and closing
    try:
        with sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES, timeout=10) as conn:
            cursor = conn.cursor()
            app_logger.info("Initializing database schema...")

            # Prepare list of valid location states for the IN constraint check
            # Need to create placeholders for SQL parameter substitution
            location_placeholders = ','.join(['?'] * len(VALID_LOCATION_STATES))
            # Create table with robust CHECK constraints
            create_table_sql = f'''
                CREATE TABLE IF NOT EXISTS tracker_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    vehicle_info TEXT NOT NULL,
                    current_location TEXT DEFAULT 'Not Started Yet' CHECK (current_location IN ({location_placeholders}) OR current_location LIKE 'Error:%'),
                    direction TEXT DEFAULT 'home_to_college' CHECK(direction IN ('home_to_college', 'college_to_home', 'unknown')),
                    fuel_level INTEGER DEFAULT 5 CHECK(fuel_level BETWEEN 0 AND 5),
                    sos_active INTEGER DEFAULT 0 CHECK(sos_active IN (0, 1)),
                    low_fuel_alert INTEGER DEFAULT 0 CHECK(low_fuel_alert IN (0, 1)),
                    discomfort_alert INTEGER DEFAULT 0 CHECK(discomfort_alert IN (0, 1)),
                    last_updated TIMESTAMP NOT NULL
                )
            '''
            cursor.execute(create_table_sql, VALID_LOCATION_STATES) # Pass states as parameters for IN clause

            # Check if the single row (id=1) exists
            cursor.execute("SELECT COUNT(*) FROM tracker_state WHERE id = 1")
            if cursor.fetchone()[0] == 0:
                app_logger.info("Tracker state row not found, inserting initial state.")
                initial_time = datetime.now()
                cursor.execute('''
                    INSERT INTO tracker_state (id, vehicle_info, current_location, direction, fuel_level, sos_active, low_fuel_alert, discomfort_alert, last_updated)
                    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
                 ''', (VEHICLE_INFO, 'Not Started Yet', 'home_to_college', 5, 0, 0, 0, initial_time))
            else:
                # Ensure vehicle info is up-to-date
                cursor.execute("UPDATE tracker_state SET vehicle_info = ? WHERE id = 1 AND vehicle_info != ?", (VEHICLE_INFO, VEHICLE_INFO))
                if cursor.rowcount > 0:
                     app_logger.info("Updated vehicle info in existing state row.")
                else:
                     app_logger.info("Database already initialized. State row exists.")

            app_logger.info("Database initialization complete.")
            # Commit happens automatically on exiting 'with' block successfully

    except sqlite3.Error as e:
        app_logger.critical(f"CRITICAL: Database initialization failed: {e}", exc_info=True)
        raise # Stop the app if DB init fails
    except Exception as e:
        app_logger.critical(f"CRITICAL: Unexpected error during DB init: {e}", exc_info=True)
        raise

def get_current_state():
    """Fetches the current tracker state from the database. Returns dict or error dict."""
    try:
        with app.app_context(): # Use app context to manage g
            db = get_db()
            # PRAGMA query_only = ON; # Consider for read-only safety if needed elsewhere
            cursor = db.execute("SELECT * FROM tracker_state WHERE id = 1")
            state_row = cursor.fetchone()
            # PRAGMA query_only = OFF;
            if state_row:
                state_dict = dict(state_row)
                if state_dict.get('last_updated') and isinstance(state_dict['last_updated'], datetime):
                     state_dict['last_updated'] = state_dict['last_updated'].isoformat()
                return state_dict
            else:
                app_logger.error("CRITICAL: State row (id=1) not found in database!")
                # Maybe try to re-insert? Or just report error.
                # init_db() # Careful with this, might mask underlying issues
                return get_default_error_state("DB Row Missing")
    except (sqlite3.Error, ConnectionError) as e:
        app_logger.error(f"Database error fetching state: {e}", exc_info=True)
        return get_default_error_state("DB Read Failed")
    except Exception as e:
        app_logger.error(f"Unexpected error fetching state: {e}", exc_info=True)
        return get_default_error_state("Unexpected Error")

def get_default_error_state(error_msg="Unknown Error"):
    """Returns a standardized error state dictionary."""
    app_logger.warning(f"Generating default error state: {error_msg}")
    return {
        'id': 1, 'vehicle_info': VEHICLE_INFO, 'current_location': f'Error: {error_msg}',
        'direction': 'unknown', 'fuel_level': 0, 'sos_active': 0,
        'low_fuel_alert': 0, 'discomfort_alert': 0,
        'last_updated': datetime.now().isoformat()
    }

def update_state(updates):
    """Validates, updates DB state, and broadcasts new state. Returns (bool, dict)."""
    if not isinstance(updates, dict) or not updates:
        app_logger.warning("Invalid or empty 'updates' dict passed to update_state.")
        return False, get_current_state()

    current_time = datetime.now()
    updates_to_apply = {'last_updated': current_time}
    valid_fields = ['current_location', 'direction', 'fuel_level', 'sos_active', 'low_fuel_alert', 'discomfort_alert']
    validation_errors = []

    # Step 1: Validate all incoming updates
    for key, value in updates.items():
        if key not in valid_fields: continue # Ignore invalid fields

        original_value = value
        validated_value = None
        error_msg = None
        try:
            if key == 'current_location':
                if value in VALID_LOCATION_STATES: validated_value = value
                else: error_msg = f"Location '{value}' is not valid."
            elif key == 'direction':
                if value in ['home_to_college', 'college_to_home', 'unknown']: validated_value = value
                else: error_msg = f"Direction '{value}' is invalid."
            elif key == 'fuel_level':
                fuel = int(value);
                if 0 <= fuel <= 5: validated_value = fuel
                else: error_msg = f"Fuel level '{value}' must be 0-5."
            elif key in ['sos_active', 'low_fuel_alert', 'discomfort_alert']:
                alert_val = int(value);
                if alert_val in [0, 1]: validated_value = alert_val
                else: error_msg = f"Alert value for {key} ('{value}') must be 0 or 1."
        except (ValueError, TypeError) as e: error_msg = f"Invalid type for {key}: '{original_value}'. Error: {e}"

        if error_msg: validation_errors.append(f"{key}: {error_msg}")
        elif validated_value is not None: updates_to_apply[key] = validated_value

    # Step 2: Check validation results
    if validation_errors:
        full_error_message = "Update validation failed: " + "; ".join(validation_errors)
        app_logger.error(full_error_message)
        return False, get_current_state()
    if len(updates_to_apply) <= 1: # Only timestamp
        app_logger.warning("No valid fields to update after validation.")
        return False, get_current_state()

    # Step 3: Prepare and Execute SQL Update
    set_clauses = [f"{key} = ?" for key in updates_to_apply.keys()]
    values = list(updates_to_apply.values())
    sql = f"UPDATE tracker_state SET {', '.join(set_clauses)} WHERE id = 1"
    app_logger.debug(f"Attempting SQL update: {sql} with values: {values}")

    try:
        with app.app_context(): # Use context for DB connection management
            db = get_db()
            cursor = db.cursor()
            cursor.execute(sql, values)

            if cursor.rowcount == 0:
                 app_logger.error("CRITICAL: Update affected 0 rows. State row (id=1) missing or no change?")
                 db.rollback()
                 return False, get_current_state()

            db.commit() # Commit the transaction
            app_logger.info(f"Database state updated successfully. Changes: {updates_to_apply}")

            # Step 4: Fetch and Broadcast the *new* complete state
            new_full_state = get_current_state() # Fetch the updated state
            if 'Error:' in new_full_state.get('current_location', ''):
                 app_logger.error("CRITICAL: Failed to fetch state *after* successful DB update!")
                 return False, new_full_state # Return failure but the error state

            socketio.emit('state_update', new_full_state, broadcast=True)
            app_logger.info(f"Broadcasted state_update event to all clients. New location: {new_full_state.get('current_location')}")
            return True, new_full_state # Success!

    except sqlite3.OperationalError as e:
         app_logger.error(f"Database locked or operational error during update: {e}", exc_info=True)
         with app.app_context(): # Attempt rollback in context
            try: db = get_db(); db.rollback()
            except Exception as rb_e: app_logger.error(f"Rollback attempt failed: {rb_e}")
         return False, get_current_state()
    except (sqlite3.Error, ConnectionError) as e:
        app_logger.error(f"Database error during update: {e}", exc_info=True)
        with app.app_context(): # Attempt rollback
            try: db = get_db(); db.rollback()
            except Exception as rb_e: app_logger.error(f"Rollback attempt failed: {rb_e}")
        return False, get_current_state()
    except Exception as e:
        app_logger.error(f"Unexpected error during update state: {e}", exc_info=True)
        with app.app_context(): # Attempt rollback
            try: db = get_db(); db.rollback()
            except Exception as rb_e: app_logger.error(f"Rollback attempt failed: {rb_e}")
        return False, get_current_state()


# --- Flask Routes ---
@app.route('/')
def index():
    """Serves the public viewer page with current state."""
    app_logger.info(f"Serving index page request from {request.remote_addr}")
    current_state = get_current_state()
    return render_template('index.html', current_state=current_state)

@app.route('/admin')
def admin():
    """Serves the admin control page. Add Auth for production!"""
    app_logger.info(f"Serving admin page request from {request.remote_addr}")
    # TODO: Implement proper authentication here
    current_state = get_current_state()
    return render_template('admin.html', locations=LOCATIONS, current_state=current_state)

@app.route('/api/state')
def api_state():
     """Optional JSON API endpoint for current state."""
     app_logger.info(f"Serving API state request from {request.remote_addr}")
     current_state = get_current_state()
     return jsonify(current_state)

# --- SocketIO Events ---
@socketio.on('connect')
def handle_connect():
    """Client connects, log and send current state."""
    client_sid = request.sid
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    app_logger.info(f"Client connected: SID={client_sid}, IP={ip_addr}")
    current_state = get_current_state()
    emit('state_update', current_state, room=client_sid) # Send only to new client

@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnects, log it."""
    app_logger.info(f"Client disconnected: SID={request.sid}")

@socketio.on_error_default # Catch unhandled socketio errors
def default_error_handler(e):
    app_logger.error(f"Unhandled SocketIO Error: {e}", exc_info=True)
    # Example: emit('server_error', {'message': 'Internal server error'}, room=request.sid)


# --- Admin Actions Handlers (Simplified Wrapper) ---
def handle_admin_action(action_name, updates, client_sid):
    """Generic handler for admin actions that trigger state updates."""
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    app_logger.info(f"Admin action '{action_name}' received from SID={client_sid}, IP={ip_addr}, Data={updates}")

    success, _ = update_state(updates) # update_state handles broadcast internally now

    if success:
        # Feedback includes the primary value changed for clarity
        changed_key = next((k for k in updates if k != 'last_updated'), None)
        value = updates.get(changed_key, 'N/A') if changed_key else 'N/A'
        emit('admin_action_success', {'action': action_name, 'value': value}, room=client_sid)
        app_logger.info(f"Admin action '{action_name}' processed successfully.")
    else:
        # update_state already logged the specific internal error
        emit('admin_action_error', {'action': action_name, 'message': 'Update failed. Check server logs.'}, room=client_sid)
        app_logger.error(f"Admin action '{action_name}' failed during processing.")

# --- Specific Admin Event Handlers ---
@socketio.on('admin_update_location')
def handle_location_update(data):
    location = data.get('location')
    if isinstance(location, str): handle_admin_action('update_location', {'current_location': location}, request.sid)
    else: emit('admin_action_error', {'action': 'update_location', 'message': 'Invalid location data type.'}, room=request.sid)

@socketio.on('admin_update_direction')
def handle_direction_update(data):
    direction = data.get('direction')
    if isinstance(direction, str): handle_admin_action('update_direction', {'direction': direction}, request.sid)
    else: emit('admin_action_error', {'action': 'update_direction', 'message': 'Invalid direction data type.'}, room=request.sid)

@socketio.on('admin_update_fuel')
def handle_fuel_update(data):
    fuel_level = data.get('fuel_level')
    if fuel_level is not None: handle_admin_action('update_fuel', {'fuel_level': fuel_level}, request.sid)
    else: emit('admin_action_error', {'action': 'update_fuel', 'message': 'Fuel level data missing.'}, room=request.sid)

# Helper for toggle actions
def handle_admin_toggle(action_name, field_name, client_sid):
    current_state = get_current_state()
    if 'Error:' in current_state.get('current_location', ''):
         app_logger.error(f"Cannot toggle {field_name} for SID={client_sid}: Failed to retrieve current state.")
         emit('admin_action_error', {'action': action_name, 'message': 'Internal error: Cannot get current state.'}, room=client_sid)
         return
    try: current_value = int(current_state.get(field_name, 0))
    except (ValueError, TypeError): current_value = 0 # Default to 0 if invalid
    if current_value not in [0, 1]: current_value = 0 # Force 0 if out of range
    new_value = 1 - current_value # Toggle
    handle_admin_action(action_name, {field_name: new_value}, client_sid)

@socketio.on('admin_toggle_sos')
def handle_toggle_sos(): handle_admin_toggle('toggle_sos', 'sos_active', request.sid)
@socketio.on('admin_toggle_low_fuel')
def handle_toggle_low_fuel(): handle_admin_toggle('toggle_low_fuel', 'low_fuel_alert', request.sid)
@socketio.on('admin_toggle_discomfort')
def handle_toggle_discomfort(): handle_admin_toggle('toggle_discomfort', 'discomfort_alert', request.sid)

# --- Main Execution Guard ---
if __name__ == '__main__':
    app_logger.info("="*30 + " Application Starting Up " + "="*30)
    try:
        init_db() # Initialize DB schema before starting server
        app_logger.info("Database initialized successfully.")

        print("\n" + "="*60)
        print("       Rahul's Realtime Journey Tracker - READY")
        print("="*60)
        print(f" > Vehicle: {VEHICLE_INFO}")
        print(f" > Database: {os.path.abspath(DATABASE)}")
        print(f" > Logging to: Console" + (f" and {os.path.abspath(LOG_FILE)}" if os.path.exists(LOG_FILE) else " (File logging failed?)"))
        print(f" > Flask Secret Key: {'Set (Hidden)' if SECRET_KEY != 'dev_secret' else 'Using Default/Random!'}")
        print("-"*60)
        host_ip = '0.0.0.0'
        port = 5000
        print(f" > Viewer URL: http://127.0.0.1:{port}/")
        print(f" > Admin URL:  http://127.0.0.1:{port}/admin")
        print(f"   (Access also via http://<your-local-ip>:{port}/)")
        print("-"*60)
        print(" > Starting Flask-SocketIO server (Press CTRL+C to stop)...")
        print("="*60 + "\n")

        # For production, use a proper WSGI server like gunicorn + eventlet/gevent
        # Example: gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app
        socketio.run(app, host=host_ip, port=port, debug=False, use_reloader=False) # Stable settings

    except (sqlite3.Error, OSError, ConnectionError, Exception) as e:
         app_logger.critical(f"FATAL: Application failed to start during initialization or server run: {e}", exc_info=True)
         print(f"\n\nFATAL ERROR: Application failed to start: {e}\nCheck logs ({LOG_FILE}) for details.\n")
    finally:
         app_logger.info("="*30 + " Application Shutting Down " + "="*30)