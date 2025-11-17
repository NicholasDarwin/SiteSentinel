const axios = require('axios');
const cheerio = require('cheerio');

async function inspectSite(url) {
  try {
    const response = await axios.get(url, {
      timeout: 15000,
      validateStatus: () => true,
      maxRedirects: 0
    });

    const $ = cheerio.load(response.data);
    
    console.log('Meta Refresh:', $('meta[http-equiv="refresh"]').attr('content'));
    console.log('Scripts (first 500 chars):');
    console.log($('script').text().substring(0, 500));
    console.log('\nHTML (first 1000 chars):');
    console.log(response.data.substring(0, 1000));
  } catch (error) {
    console.error('Error:', error.message);
  }
}

inspectSite('https://hk.jayantwhaling.shop/iV4w2ggznMEm24XVr/vLlnm?param_4=894697&param_5=5084572210725997861');
