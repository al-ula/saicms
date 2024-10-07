use super::account::Account;
use crate::db::Db;
use bincode;
use redb::{ReadableTable, TableDefinition};

const TABLE: TableDefinition<u128, Vec<u8>> = TableDefinition::new("account");

impl Db {
    pub fn insert_account(&self, account: &Account) -> Result<(), redb::Error> {
        let value = bincode::serialize(account).unwrap();
        let write = self.db.begin_write()?;
        {
            let mut table = write.open_table(TABLE)?;
            table.insert(account.get_id(), value)?;
        }
        write.commit().map_err(|e| e.into())
    }

    pub fn query_account_by_id(&self, id: u128) -> Result<Account, redb::Error> {
        let db = self.db.clone();
        let read = db.begin_read()?;
        let table = read.open_table(TABLE)?;
        let value = table
            .get(id)?
            .ok_or(redb::Error::TableDoesNotExist("account".to_string()))?;
        Ok(bincode::deserialize(&value.value()).unwrap())
    }

    pub fn query_account_by_username(
        &self,
        username: &str,
    ) -> Result<Account, Box<dyn Send + Sync + std::error::Error>> {
        let db = self.db.clone();
        let read = db.begin_read()?;
        let table = read.open_table(TABLE)?;
        let value = table.iter().map(|t| {
            for entry in t {
                let entry = entry.map_err(|e| {
                    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(e);
                    err
                })?;
                let entry_v = entry.1.value();
                let account = bincode::deserialize::<Account>(&entry_v).map_err(|e| {
                    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(e);
                    err
                })?;
                if account.get_username() != username {
                    continue;
                }
                return Ok(account);
            }
            let err: Box<dyn std::error::Error + Send + Sync> =
                Box::new(std::io::Error::from(std::io::ErrorKind::NotFound));
            Err(err)
        })??;
        Ok(value)
    }

    pub fn query_account_by_email(
        &self,
        email: &str,
    ) -> Result<Account, Box<dyn Send + Sync + std::error::Error>> {
        let db = self.db.clone();
        let read = db.begin_read()?;
        let table = read.open_table(TABLE)?;
        let value = table.iter()?;
        for entry in value {
            let entry = entry.map_err(|e| {
                let err: Box<dyn std::error::Error + Send + Sync> = Box::new(e);
                err
            })?;
            let entry = entry.1.value();
            let account = bincode::deserialize::<Account>(&entry).map_err(|e| {
                let err: Box<dyn std::error::Error + Send + Sync> = Box::new(e);
                err
            })?;
            if account.get_email() != email {
                continue;
            }
            return Ok(account);
        }
        let err: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::from(std::io::ErrorKind::NotFound));
        Err(err)
    }

    pub fn query_all_account(
        &self,
    ) -> Result<Vec<Account>, Box<dyn Send + Sync + std::error::Error>> {
        let db = self.db.clone();
        let read = db.begin_read()?;
        let table = read.open_table(TABLE)?;
        let value = table.iter()?;
        let mut v = vec![];
        for entry in value {
            let entry = entry.map_err(|e| {
                let err: Box<dyn std::error::Error + Send + Sync> = Box::new(e);
                err
            })?;
            let entry = entry.1.value();
            let account = bincode::deserialize::<Account>(&entry).map_err(|e| {
                let err: Box<dyn std::error::Error + Send + Sync> = Box::new(e);
                err
            })?;
            v.push(account);
        }
        Ok(v)
    }
}
