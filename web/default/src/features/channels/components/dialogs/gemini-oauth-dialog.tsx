/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { useMemo, useState, type ChangeEvent } from 'react'
import { Check, Copy, ExternalLink, Loader2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { tryPrettyJson } from '@/lib/utils'
import { useCopyToClipboard } from '@/hooks/use-copy-to-clipboard'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { completeGeminiOAuth, startGeminiOAuth } from '../../api'

type GeminiOAuthDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  onKeyGenerated: (key: string) => void
}

const DEFAULT_REDIRECT_URI = 'http://localhost:1455/oauth2callback'

function createInitialState() {
  return {
    clientId: '',
    clientSecret: '',
    projectId: '',
    redirectUri: DEFAULT_REDIRECT_URI,
    authorizeUrl: '',
    callbackUrl: '',
    isStarting: false,
    isCompleting: false,
  }
}

export function GeminiOAuthDialog({
  open,
  onOpenChange,
  onKeyGenerated,
}: GeminiOAuthDialogProps) {
  const { t } = useTranslation()
  const { copiedText, copyToClipboard } = useCopyToClipboard({ notify: false })

  const [state, setState] = useState(createInitialState)

  const canCopyAuthorizeUrl = Boolean(state.authorizeUrl && !state.isStarting)
  const canComplete = useMemo(
    () =>
      Boolean(
        state.callbackUrl.trim() &&
        state.clientId.trim() &&
        state.projectId.trim()
      ) && !state.isCompleting,
    [state.callbackUrl, state.clientId, state.projectId, state.isCompleting]
  )

  const updateField =
    (field: keyof typeof state) => (event: ChangeEvent<HTMLInputElement>) => {
      setState((prev) => ({ ...prev, [field]: event.target.value }))
    }

  const handleOpenChange = (nextOpen: boolean) => {
    if (!nextOpen) {
      setState(createInitialState())
    }
    onOpenChange(nextOpen)
  }

  const handleStart = async () => {
    if (!state.clientId.trim()) {
      toast.error(t('OAuth Client ID is required'))
      return
    }

    setState((prev) => ({ ...prev, isStarting: true }))
    try {
      const res = await startGeminiOAuth({
        client_id: state.clientId.trim(),
        redirect_uri: state.redirectUri.trim() || DEFAULT_REDIRECT_URI,
      })
      if (!res.success) {
        throw new Error(res.message || 'Failed to start OAuth')
      }

      const url = res.data?.authorize_url || ''
      if (!url) {
        throw new Error('Missing authorize_url in response')
      }

      setState((prev) => ({
        ...prev,
        authorizeUrl: url,
        redirectUri: res.data?.redirect_uri || prev.redirectUri,
      }))
      try {
        window.open(url, '_blank', 'noopener,noreferrer')
        toast.success(t('Opened authorization page'))
      } catch (error) {
        // eslint-disable-next-line no-console
        console.warn('Failed to open authorization page:', error)
        toast.warning(t('Please manually copy and open the authorization link'))
      }
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : t('OAuth start failed')
      )
    } finally {
      setState((prev) => ({ ...prev, isStarting: false }))
    }
  }

  const handleComplete = async () => {
    if (!canComplete) return
    setState((prev) => ({ ...prev, isCompleting: true }))
    try {
      const res = await completeGeminiOAuth({
        input: state.callbackUrl.trim(),
        client_id: state.clientId.trim(),
        client_secret: state.clientSecret.trim(),
        project_id: state.projectId.trim(),
        redirect_uri: state.redirectUri.trim() || DEFAULT_REDIRECT_URI,
      })
      if (!res.success) {
        throw new Error(res.message || 'OAuth failed')
      }

      const rawKey = res.data?.key || ''
      if (!rawKey) {
        throw new Error('Missing key in response')
      }

      onKeyGenerated(tryPrettyJson(rawKey))
      toast.success(t('Credential generated'))
      handleOpenChange(false)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('OAuth failed'))
    } finally {
      setState((prev) => ({ ...prev, isCompleting: false }))
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className='sm:max-w-2xl'>
        <DialogHeader>
          <DialogTitle>{t('Gemini Authorization')}</DialogTitle>
          <DialogDescription>
            {t(
              'Generate a Gemini OAuth credential and paste it into the channel key field.'
            )}
          </DialogDescription>
        </DialogHeader>

        <div className='space-y-4'>
          <Alert>
            <AlertDescription>
              {t(
                '1) Click "Open authorization page" and complete login. 2) Your browser may redirect to localhost (it is OK if the page does not load). 3) Copy the full URL from the address bar and paste it below. 4) Click "Generate credential".'
              )}
            </AlertDescription>
          </Alert>

          <div className='grid gap-3 sm:grid-cols-2'>
            <div className='space-y-2'>
              <div className='text-sm font-medium'>{t('OAuth Client ID')}</div>
              <Input
                value={state.clientId}
                onChange={updateField('clientId')}
                placeholder={t('OAuth Client ID')}
                autoComplete='off'
                spellCheck={false}
              />
            </div>
            <div className='space-y-2'>
              <div className='text-sm font-medium'>
                {t('OAuth Client Secret')}
              </div>
              <Input
                value={state.clientSecret}
                onChange={updateField('clientSecret')}
                placeholder={t('OAuth Client Secret')}
                autoComplete='off'
                spellCheck={false}
              />
            </div>
            <div className='space-y-2'>
              <div className='text-sm font-medium'>
                {t('Google Cloud Project ID')}
              </div>
              <Input
                value={state.projectId}
                onChange={updateField('projectId')}
                placeholder='my-gemini-project'
                autoComplete='off'
                spellCheck={false}
              />
            </div>
            <div className='space-y-2'>
              <div className='text-sm font-medium'>{t('Redirect URI')}</div>
              <Input
                value={state.redirectUri}
                onChange={updateField('redirectUri')}
                placeholder={DEFAULT_REDIRECT_URI}
                autoComplete='off'
                spellCheck={false}
              />
            </div>
          </div>

          <div className='text-muted-foreground text-xs'>
            {t(
              'Use the Google Cloud project that has the Gemini API enabled for x-goog-user-project.'
            )}
          </div>

          <div className='flex flex-wrap gap-2'>
            <Button onClick={handleStart} disabled={state.isStarting}>
              {state.isStarting ? (
                <Loader2 className='mr-2 h-4 w-4 animate-spin' />
              ) : (
                <ExternalLink className='mr-2 h-4 w-4' />
              )}
              {t('Open authorization page')}
            </Button>

            <Button
              type='button'
              variant='outline'
              disabled={!canCopyAuthorizeUrl}
              onClick={async () => {
                if (!state.authorizeUrl) return
                await copyToClipboard(state.authorizeUrl)
              }}
              aria-label={t('Copy authorization link')}
              title={t('Copy authorization link')}
            >
              {copiedText === state.authorizeUrl ? (
                <Check className='mr-2 h-4 w-4 text-green-600' />
              ) : (
                <Copy className='mr-2 h-4 w-4' />
              )}
              {t('Copy authorization link')}
            </Button>
          </div>

          <div className='space-y-2'>
            <div className='text-sm font-medium'>{t('Callback URL')}</div>
            <Input
              value={state.callbackUrl}
              onChange={updateField('callbackUrl')}
              placeholder={t(
                'Paste the full callback URL (includes code & state)'
              )}
              autoComplete='off'
              spellCheck={false}
            />
            <div className='text-muted-foreground text-xs'>
              {t(
                'Tip: The generated key is a JSON credential including access_token / refresh_token / project_id.'
              )}
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button
            type='button'
            variant='outline'
            onClick={() => handleOpenChange(false)}
            disabled={state.isStarting || state.isCompleting}
          >
            {t('Cancel')}
          </Button>
          <Button onClick={handleComplete} disabled={!canComplete}>
            {state.isCompleting && (
              <Loader2 className='mr-2 h-4 w-4 animate-spin' />
            )}
            {state.isCompleting ? t('Generating...') : t('Generate credential')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
