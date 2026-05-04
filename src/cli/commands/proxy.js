import { ProxyScraper } from '../../core/proxy/proxy-scraper.js';
import logger from '../../utils/logger.js';

/**
 * Handle proxy command
 */
export async function handleProxy(options) {
  const scraper = new ProxyScraper({
    protocol: options.protocol || 'http',
    country: options.country || 'all',
  });

  try {
    if (options.fetch) {
      logger.info('[Proxy] Fetching fresh proxies from multiple sources...');
      logger.info('[Proxy] Sources: ProxyScrape, free-proxy-list, Geonode, proxy-list.download, spys.me');

      const proxies = await scraper.fetchProxies({
        protocol: options.protocol || 'http',
        country: options.country || 'all',
      });

      logger.success(`[Proxy] Fetched ${proxies.length} proxies`);

      // Auto-validate if requested
      if (options.validate) {
        logger.info('[Proxy] Validating proxies...');
        const working = await scraper.validateProxies({ concurrent: 100 });
        logger.success(`[Proxy] ${working.length}/${proxies.length} proxies are working`);

        // Show top 10 fastest
        logger.info('\nTop 10 fastest proxies:');
        working.slice(0, 10).forEach((p, i) => {
          logger.info(`  ${i + 1}. ${p.url} (${p.responseTime}ms)`);
        });
      }
    }
    else if (options.validate) {
      logger.info('[Proxy] Validating cached proxies...');
      const count = scraper.getCount();

      if (count.total === 0) {
        logger.warn('[Proxy] No cached proxies. Run --fetch first.');
        return;
      }

      const working = await scraper.validateProxies({ concurrent: 100 });
      logger.success(`[Proxy] ${working.length}/${count.total} proxies are working`);

      // Show top 10
      logger.info('\nTop 10 fastest proxies:');
      working.slice(0, 10).forEach((p, i) => {
        logger.info(`  ${i + 1}. ${p.url} (${p.responseTime}ms)`);
      });
    }
    else if (options.list) {
      const working = scraper.getWorking();
      if (working.length === 0) {
        logger.warn('[Proxy] No working proxies cached. Run --fetch --validate first.');
        return;
      }

      logger.info(`\nWorking proxies (${working.length}):`);
      working.forEach((p, i) => {
        logger.info(`  ${i + 1}. ${p.url} (${p.responseTime || '?'}ms)`);
      });
    }
    else if (options.count) {
      const count = scraper.getCount();
      logger.info(`[Proxy] Total: ${count.total}, Working: ${count.working}`);
    }
    else {
      logger.info('Proxy Management Commands:');
      logger.info('  --fetch              Fetch fresh proxies from ProxyScrape & other sources');
      logger.info('  --validate           Test and validate proxies');
      logger.info('  --fetch --validate   Fetch and validate in one step');
      logger.info('  --list               List working proxies');
      logger.info('  --count              Show proxy count');
      logger.info('  --protocol <type>    Protocol: http, socks4, socks5');
      logger.info('  --country <code>     Country code: US, ID, SG, etc.');
      logger.info('\nExamples:');
      logger.info('  recon-tool proxy --fetch --validate');
      logger.info('  recon-tool proxy --fetch --protocol socks5');
      logger.info('  recon-tool proxy --fetch --country ID');
    }
  } catch (error) {
    logger.error(`Proxy error: ${error.message}`);
  }
}

export default handleProxy;
