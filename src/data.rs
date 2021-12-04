use crate::error::Error;
use serde_json::Value;

pub struct Friend {
    pub id: String,
    pub pid: String,
    pub puuid: String,
    pub smid: u64,
    pub name: String,
    pub note: String,
    pub game_name: String,
    pub status_msg: String,
    pub availability: String,
    //last_seen_online: u64,
}

pub struct FriendList(pub Vec<Friend>);

impl FriendList {
    pub fn fron_json_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let json = serde_json::from_slice::<Value>(&bytes)?;
        let json = json.as_array().ok_or(Error::wrong_value_type("root"))?;
        let mut vec = Vec::<Friend>::new();
        for item in json {
            vec.push(Friend {
                id: item
                    .get("id")
                    .ok_or(Error::value_not_found("id"))?
                    .as_str()
                    .ok_or(Error::wrong_value_type("id"))?
                    .to_owned(),
                pid: item
                    .get("pid")
                    .ok_or(Error::value_not_found("pid"))?
                    .as_str()
                    .ok_or(Error::wrong_value_type("pid"))?
                    .to_owned(),
                puuid: item
                    .get("puuid")
                    .ok_or(Error::value_not_found("puuid"))?
                    .as_str()
                    .ok_or(Error::wrong_value_type("puuid"))?
                    .to_owned(),
                smid: item
                    .get("summonerId")
                    .ok_or(Error::value_not_found("summonerId"))?
                    .as_u64()
                    .ok_or(Error::wrong_value_type("summonerId"))?,
                name: item
                    .get("name")
                    .ok_or(Error::value_not_found("name"))?
                    .as_str()
                    .ok_or(Error::wrong_value_type("name"))?
                    .to_owned(),
                note: item
                    .get("note")
                    .ok_or(Error::value_not_found("note"))?
                    .as_str()
                    .ok_or(Error::wrong_value_type("note"))?
                    .to_owned(),
                game_name: item
                    .get("gameName")
                    .ok_or(Error::value_not_found("gameName"))?
                    .as_str()
                    .ok_or(Error::wrong_value_type("gameName"))?
                    .to_owned(),
                status_msg: item
                    .get("statusMessage")
                    .ok_or(Error::value_not_found("statusMessage"))?
                    .as_str()
                    .ok_or(Error::wrong_value_type("statusMessage"))?
                    .to_owned(),
                availability: item
                    .get("availability")
                    .ok_or(Error::value_not_found("availability"))?
                    .as_str()
                    .ok_or(Error::wrong_value_type("availability"))?
                    .to_owned(),
            });
        }
        Ok(FriendList(vec))
    }
}

impl std::fmt::Display for FriendList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut output = String::new();
        for v in &self.0 {
            output.push_str(&format!(
                "-> {}  {:7}  {}\n",
                v.puuid, v.availability, v.name
            ));
        }
        write!(f, "{}", output)
    }
}

impl std::fmt::Display for Friend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut output = String::new();
        output.push_str(&format!("id: ............. {}\n", self.id));
        output.push_str(&format!("pid: ............ {}\n", self.pid));
        output.push_str(&format!("puuid: .......... {}\n", self.puuid));
        output.push_str(&format!("smid: ........... {}\n", self.smid));
        output.push_str(&format!("name: ........... {}\n", self.name));
        output.push_str(&format!("game_name: ...... {}\n", self.game_name));
        output.push_str(&format!("note: ........... {}\n", self.note));
        output.push_str(&format!("status: ......... {}\n", self.status_msg));
        output.push_str(&format!("availability: ... {}\n", self.availability));
        write!(f, "{}", output)
    }
}
