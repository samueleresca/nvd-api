use std::fmt::Display;

use async_trait::async_trait;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::Client;
use serde::Deserialize;

pub(crate) const DELIMITER: &str = "&";
pub(crate) const ASSIGNER: &str = "=";
pub(crate) const CVE_API_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
// https://url.spec.whatwg.org/
#[allow(dead_code)]
const FRAGEMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'#');

#[async_trait]
pub(crate) trait RequestExecutor<T>
where
    Self: Display,
    T: for<'a> Deserialize<'a>,
{
    fn get_base_url(&self) -> &String;
    fn get_http_client(&self) -> &Client;
    fn get_api_key(&self) -> &Option<String>;

    // Associated function signature; `Self` refers to the implementor type.
    async fn execute(&self) -> Result<T, reqwest::Error> {
        let data = &self.to_string();
        let encoder = utf8_percent_encode(data, FRAGEMENT);
        let encoded_data: String = encoder.collect();
        let full_url = Self::get_base_url(self).to_owned() + "?" + &encoded_data;
        let mut builder = Self::get_http_client(self).get(full_url);

        match &Self::get_api_key(self) {
            Some(v) => {
                builder = builder.header("api_key", v.to_string());
            }
            None => {}
        }

        Ok(builder.send().await?.json::<T>().await?)
    }
}
