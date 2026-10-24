<script>
  /** "Open error log" after a message that points at the log, so nobody has to find the folder by hand. */
  import { call } from '../lib/api.js';
  import { okOrToast, mentionsErrorLog } from '../lib/toast.js';

  let { text = '' } = $props();

  async function open() {
    okOrToast(await call('errorlog_open'), 'Error log folder not opened');
  }
</script>

{#if mentionsErrorLog(text)}<button type="button" class="log-link" onclick={open}>Open error log</button>{/if}

<style>
  .log-link {
    border: 0; background: none; padding: 0 0 0 6px; font: inherit; font-size: inherit;
    color: var(--link); cursor: pointer; white-space: nowrap;
  }
  .log-link:hover { text-decoration: underline; }
</style>
