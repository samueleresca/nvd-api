use std::fmt::Display;

use async_trait::async_trait;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::Client;
use serde::Deserialize;

pub(crate) const DELIMITER: &str = "&";
pub(crate) const ASSIGNER: &str = "=";
pub(crate) const BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/";
// https://url.spec.whatwg.org/
#[allow(dead_code)]
const FRAGEMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'#');

#[async_trait]
pub trait RequestExecutor<T>
where
    Self: Display,
    T: for<'a> Deserialize<'a>,
{
    fn get_base_url(&self) -> &String;
    fn get_http_client(&self) -> &Client;
    fn get_api_key(&self) -> &Option<String>;

    async fn execute(&self) -> Result<T, reqwest::Error> {
        let data = &self.to_string();
        let encoder = utf8_percent_encode(data, FRAGEMENT);
        let encoded_data: String = encoder.collect();
        let full_url = self.get_base_url().to_owned() + "?" + &encoded_data;

        let mut builder = self.get_http_client().get(full_url);

        match &self.get_api_key() {
            Some(v) => {
                builder = builder.header("api_key", v.to_string());
            }
            None => {}
        }
        Ok(builder.send().await?.json::<T>().await?)
    }
}

pub mod cpe;
pub mod cpe_match;
pub mod cve;
pub mod cve_change_history;
