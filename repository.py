from models import db, MasterConfig, Client, SyncHistory, SchedulePreference
from storage import encrypt_api_key, decrypt_api_key

# MasterConfig CRUD
def get_master_config():
    record = MasterConfig.query.first()
    if not record:
        return None
    return {'id': record.id, 'address': record.address, 'api_key': decrypt_api_key(record.api_key)}

def set_master_config(address, api_key):
    enc = encrypt_api_key(api_key)
    record = MasterConfig.query.first()
    if record:
        record.address = address
        record.api_key = enc
    else:
        record = MasterConfig(address=address, api_key=enc)
        db.session.add(record)
    try:
        db.session.commit()
        return True
    except:
        db.session.rollback()
        return False

# Client CRUD
def add_client(label, device_id, address, api_key, sync_enabled=True):
    enc = encrypt_api_key(api_key)
    client = Client(label=label, device_id=device_id, address=address, api_key=enc, sync_enabled=sync_enabled)
    db.session.add(client)
    try:
        db.session.commit()
        return client.id
    except:
        db.session.rollback()
        return None

def get_client(client_id):
    client = Client.query.get(client_id)
    if not client:
        return None
    return {'id': client.id, 'label': client.label, 'device_id': client.device_id,
            'address': client.address, 'api_key': decrypt_api_key(client.api_key), 'sync_enabled': client.sync_enabled}

def list_clients():
    out = []
    for c in Client.query.all():
        out.append({'id': c.id, 'label': c.label, 'device_id': c.device_id,
                    'address': c.address, 'api_key': decrypt_api_key(c.api_key), 'sync_enabled': c.sync_enabled})
    return out

def update_client(client_id, **kwargs):
    client = Client.query.get(client_id)
    if not client:
        return False
    for field in ('label','device_id','address','sync_enabled'):
        if field in kwargs and kwargs[field] is not None:
            setattr(client, field, kwargs[field])
    if 'api_key' in kwargs and kwargs['api_key'] is not None:
        client.api_key = encrypt_api_key(kwargs['api_key'])
    try:
        db.session.commit()
        return True
    except:
        db.session.rollback()
        return False

def delete_client(client_id):
    client = Client.query.get(client_id)
    if not client:
        return False
    db.session.delete(client)
    try:
        db.session.commit()
        return True
    except:
        db.session.rollback()
        return False

# SyncHistory CRUD
def add_sync_history(client_id, status, message):
    event = SyncHistory(client_id=client_id, status=status, message=message)
    db.session.add(event)
    try:
        db.session.commit()
        return event.id
    except:
        db.session.rollback()
        return None

def list_sync_history(client_id=None):
    query = SyncHistory.query
    if client_id:
        query = query.filter_by(client_id=client_id)
    records = query.order_by(SyncHistory.timestamp.desc()).all()
    return [
        {'id': r.id, 'client_id': r.client_id, 'status': r.status, 'message': r.message, 'timestamp': r.timestamp.isoformat()}
        for r in records
    ]

# SchedulePreference CRUD
def get_schedule_preferences():
    record = SchedulePreference.query.first()
    if not record:
        return None
    return {
        'frequency': record.frequency,
        'custom_type': record.custom_type,
        'interval_value': record.interval_value,
        'interval_unit': record.interval_unit,
        'sync_time': record.sync_time,
        'sync_days': record.sync_days,
        'show_notifications': record.show_notifications,
        'quiet_hours_enabled': record.quiet_hours_enabled,
        'quiet_hours_start': record.quiet_hours_start,
        'quiet_hours_end': record.quiet_hours_end
    }

def set_schedule_preferences(frequency=None, custom_type=None, interval_value=None, interval_unit=None, sync_time=None, sync_days=None, show_notifications=None, quiet_hours_enabled=None, quiet_hours_start=None, quiet_hours_end=None):
    record = SchedulePreference.query.first()
    if record:
        for field in ['frequency','custom_type','interval_value','interval_unit','sync_time','sync_days','show_notifications','quiet_hours_enabled','quiet_hours_start','quiet_hours_end']:
            val = locals()[field]
            if val is not None:
                setattr(record, field, val)
    else:
        record = SchedulePreference(
            frequency=frequency,
            custom_type=custom_type,
            interval_value=interval_value,
            interval_unit=interval_unit,
            sync_time=sync_time,
            sync_days=sync_days,
            show_notifications=show_notifications,
            quiet_hours_enabled=quiet_hours_enabled,
            quiet_hours_start=quiet_hours_start,
            quiet_hours_end=quiet_hours_end
        )
        db.session.add(record)
    try:
        db.session.commit()
        return True
    except:
        db.session.rollback()
        return False

# TODO: further repository functions
