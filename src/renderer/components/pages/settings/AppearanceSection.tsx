import { Palette, RotateCcw } from "lucide-react";
import { useState, type CSSProperties } from "react";
import { useAppData } from "../../../hooks/useAppData.js";
import { useResolvedTheme, useSystemPrefersDark } from "../../../hooks/useResolvedTheme.js";
import { rgbToHex } from "../../../lib/theme.js";
import { DEFAULT_CUSTOM_THEME } from "../../../../shared/defaults.js";
import type { AppSettings, ThemeMode } from "../../../../shared/types.js";
import { Badge, Button, Card, CardHeader, Segmented, StatusDot, type SegmentedOption } from "../../ui/index.js";
import { ColorField } from "./ColorField.js";
import {
  coloursAreDefault,
  colourHex,
  contrastChecks,
  PALETTE_FIELD_SPECS,
  platformCopy,
  sectionElementId,
  signalFieldSpecs,
  withColour,
  type ColourFieldSpec,
  type ColourKey
} from "./settings-model.js";
import type { SettingsSaver } from "./useSettingsSaver.js";

/** Colour pickers stream values while dragging; save once they settle. */
const COLOUR_SAVE_DEBOUNCE_MS = 350;

interface MiniColors {
  bg: string;
  surface: string;
  text: string;
  border: string;
}

const DARK_MINI: MiniColors = { bg: "#0A0B0D", surface: "#14161A", text: "#F3F1EC", border: "#2A2E35" };
const LIGHT_MINI: MiniColors = { bg: "#F3F3F0", surface: "#FFFFFF", text: "#15161A", border: "#DADAD3" };

/** A tiny app window in the given colours (theme picker thumbnails). */
function MiniWindow({ colors, cut = false }: { colors: MiniColors; cut?: boolean }): JSX.Element {
  const style = { "--tb": colors.bg, "--ts": colors.surface, "--tt": colors.text, "--tl": colors.border } as CSSProperties;
  return (
    <span className={cut ? "st-mini st-mini-cut" : "st-mini"} style={style}>
      <span className="st-mini-side">
        <span className="st-mini-ln" />
        <span className="st-mini-ln" />
        <span className="st-mini-ln" />
      </span>
      <span className="st-mini-main">
        <span className="st-mini-card">
          <span className="st-mini-bar" />
          <span className="st-mini-bar st-s" />
          <span className="st-mini-pill" />
        </span>
      </span>
    </span>
  );
}

function ThemeOption({ name, children }: { name: string; children: JSX.Element | JSX.Element[] }): JSX.Element {
  return (
    <>
      <span className="st-thumb" aria-hidden="true">
        {children}
      </span>
      <span className="st-theme-name">{name}</span>
    </>
  );
}

export function AppearanceSection({ settings, save }: { settings: AppSettings; save: SettingsSaver["save"] }): JSX.Element {
  const { environment, toast } = useAppData();
  const copy = platformCopy(environment.platform);
  const resolved = useResolvedTheme(settings);
  const systemDark = useSystemPrefersDark();
  const [drafts, setDrafts] = useState<Partial<Record<ColourKey, string>>>({});
  const theme = settings.customTheme;
  const mode = settings.theme;
  const custom = mode === "custom";

  const customMini: MiniColors = {
    bg: rgbToHex(theme.background),
    surface: rgbToHex(theme.surface),
    text: rgbToHex(theme.text),
    border: rgbToHex(theme.border)
  };
  const themeOptions: Array<SegmentedOption<ThemeMode>> = [
    {
      value: "system",
      ariaLabel: "System",
      label: (
        <ThemeOption name="System">
          <MiniWindow colors={DARK_MINI} />
          <MiniWindow colors={LIGHT_MINI} cut />
        </ThemeOption>
      )
    },
    { value: "light", ariaLabel: "Light", label: <ThemeOption name="Light"><MiniWindow colors={LIGHT_MINI} /></ThemeOption> },
    { value: "dark", ariaLabel: "Dark", label: <ThemeOption name="Dark"><MiniWindow colors={DARK_MINI} /></ThemeOption> },
    { value: "custom", ariaLabel: "Custom", label: <ThemeOption name="Custom"><MiniWindow colors={customMini} /></ThemeOption> }
  ];
  const themeHints: Record<ThemeMode, string> = {
    system: `Follows ${copy.osName} and switches the moment it does. ${systemDark ? "Dark" : "Light"} right now.`,
    light: `Always light, whatever ${copy.osName} uses.`,
    dark: `Always dark, whatever ${copy.osName} uses.`,
    custom: "Surfaces, text and borders come from your palette below. Signal colours still apply."
  };

  const setColour = (key: ColourKey, hex: string): void => {
    save({ customTheme: withColour(settings.customTheme, key, hex, resolved) }, { debounceMs: COLOUR_SAVE_DEBOUNCE_MS });
  };
  const setDraft = (key: ColourKey, value: string | undefined): void => {
    setDrafts((current) => {
      if (value === undefined) {
        if (!(key in current)) {
          return current;
        }
        const next = { ...current };
        delete next[key];
        return next;
      }
      return { ...current, [key]: value };
    });
  };

  const resetColours = (): void => {
    const previous = settings.customTheme;
    setDrafts({});
    save({ customTheme: { ...DEFAULT_CUSTOM_THEME } });
    toast({
      tone: "info",
      title: "Colours reset to defaults",
      message: "Your theme choice stays the same.",
      action: { label: "Undo", icon: RotateCcw, placement: "side", onClick: () => save({ customTheme: previous }) }
    });
  };

  const renderField = (spec: ColourFieldSpec<ColourKey>, disabled: boolean): JSX.Element => (
    <ColorField
      key={spec.key}
      name={spec.name}
      hint={spec.hint}
      hex={colourHex(theme, spec.key, resolved)}
      draft={drafts[spec.key]}
      disabled={disabled}
      onDraft={(raw, hex) => {
        setDraft(spec.key, raw);
        if (hex) {
          setColour(spec.key, hex);
        }
      }}
      onPick={(hex) => {
        setDraft(spec.key, undefined);
        setColour(spec.key, hex);
      }}
      onDraftEnd={() => setDraft(spec.key, undefined)}
    />
  );

  const contrast = contrastChecks(theme, mode, resolved);

  return (
    <Card id={sectionElementId("appearance")} className="st-section" rise={4} aria-labelledby="st-appearance-h" tabIndex={-1}>
      <CardHeader
        level={2}
        titleId="st-appearance-h"
        icon={Palette}
        title="Appearance"
        sub="Theme and colours repaint the whole app as you pick them."
        tools={
          <Button variant="ghost" size="sm" icon={RotateCcw} disabled={coloursAreDefault(theme)} onClick={resetColours}>
            Reset to defaults
          </Button>
        }
      />

      <div className="stack-sm">
        <span className="label" aria-hidden="true">
          Theme
        </span>
        <Segmented
          className="st-theme"
          block
          tall
          ariaLabel="Theme"
          value={mode}
          options={themeOptions}
          onChange={(next) => save({ theme: next })}
        />
        <span className="hint anim-swap" key={`hint-${mode}`}>
          {themeHints[mode]}
        </span>
      </div>

      <hr className="divider" />

      <div className="stack">
        <div className="st-block-head">
          <span className="st-block-title">Signal colours</span>
          <span className="hint">
            Used in every theme. Success and Danger start from the theme’s own shade until you change them. Pick a colour or type its HEX code.
          </span>
        </div>
        <div className="st-colors">{signalFieldSpecs(copy.successHint).map((spec) => renderField(spec, false))}</div>
      </div>

      <div className="st-palette" data-active={custom ? "true" : "false"}>
        <div className="st-palette-head">
          <div className="stack-sm st-palette-copy">
            <span className="st-block-title">
              Custom palette
              <Badge tone={custom ? "accent" : "outline"}>{custom ? "In use" : "Only with Custom"}</Badge>
            </span>
            <span className="hint">Surfaces, text and borders. Hover, soft and terminal tones are worked out from these five.</span>
          </div>
          {custom ? null : (
            <Button size="sm" icon={Palette} onClick={() => save({ theme: "custom" })}>
              Use Custom theme
            </Button>
          )}
        </div>
        <div className="st-colors st-palette-grid">{PALETTE_FIELD_SPECS.map((spec) => renderField(spec, !custom))}</div>
      </div>

      <div className="st-contrast" aria-live="polite">
        <span className="eyebrow">Contrast check</span>
        {contrast.checks.map((check) => (
          <span className="st-cc" key={check.id}>
            <StatusDot tone={check.tone} />
            {check.label}
            <span className="mono">{check.value}</span>· {check.verdict}
          </span>
        ))}
        <span className="st-cc-note">{contrast.note}</span>
      </div>
    </Card>
  );
}
