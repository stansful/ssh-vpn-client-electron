import { Check, ClipboardPaste, Copy, Ellipsis, Globe, Link, Pencil, Pin, RefreshCw, Trash2, TriangleAlert, type LucideIcon } from "lucide-react";
import {
  memo,
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type MouseEvent
} from "react";
import type { ProxyProfile, ProxyProfileSource } from "../../../../shared/types.js";
import { MAX_PROXY_PROFILE_NAME_LENGTH, normalizeProxyProfileName } from "../../../../shared/validation.js";
import { ActionMenu, Badge, Button, cx, Icon, IconButton, Spinner, StatusDot, type ActionMenuItem } from "../../ui/index.js";
import { presentProfileCard, RENAME_FIELD_COPY, sourceLabel, sourceTitle, type XraySession } from "./profile-presenter.js";

const SOURCE_ICON: Record<ProxyProfileSource, LucideIcon> = {
  remote: Globe,
  clipboard: ClipboardPaste,
  manual: Link
};

export interface ProfileCardProps {
  profile: ProxyProfile;
  /** Connect uses this profile (next time, if another one runs now). */
  selected: boolean;
  /** The running Xray session, if any. */
  session?: XraySession;
  /** Position in the grid, for the entrance stagger. */
  index: number;
  /** Playing its removal animation. */
  leaving: boolean;
  /** Show the F2 hint next to Rename (Windows and Linux; F2 works everywhere). */
  renameKeyHint: boolean;
  onSelect: (profile: ProxyProfile) => void;
  onTogglePin: (profile: ProxyProfile) => void;
  onRemove: (profile: ProxyProfile) => void;
  /** Saves a normalized name; "" brings back the name in the link. */
  onRename: (profile: ProxyProfile, name: string) => void;
  onCopyLink: (profile: ProxyProfile) => void;
}

/** Cancel and Save keep focus in the name field, so a press on them doesn't count as clicking away. */
function keepFieldFocus(event: MouseEvent): void {
  event.preventDefault();
}

/**
 * One profile. The whole card is the select button (`.pf-hit` under the
 * content); Pin and ⋯ sit on top of it in the footer. ⋯, a right-click or
 * Shift+F10 open the action menu (Rename, Copy link, Remove); F2 renames and
 * Delete removes from the focused card. Rename edits the name in place.
 */
export const ProfileCard = memo(function ProfileCard({
  profile,
  selected,
  session,
  index,
  leaving,
  renameKeyHint,
  onSelect,
  onTogglePin,
  onRemove,
  onRename,
  onCopyLink
}: ProfileCardProps): JSX.Element {
  const view = useMemo(() => presentProfileCard(profile, { selectedId: selected ? profile.id : undefined, session }), [profile, selected, session]);
  const { state } = view;
  const insecureId = useId();
  const menuId = useId();
  const renameHelpId = useId();
  const articleRef = useRef<HTMLElement>(null);
  const hitRef = useRef<HTMLButtonElement>(null);
  const moreRef = useRef<HTMLButtonElement>(null);
  const menuReturnRef = useRef<HTMLElement | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const editActsRef = useRef<HTMLSpanElement>(null);
  const [menu, setMenu] = useState<{ open: boolean; point: { x: number; y: number } | null }>({ open: false, point: null });
  const [editing, setEditing] = useState(false);
  // Shown without the swap-in: the name at mount or when the editor opened, so Cancel doesn't animate.
  const [quietName, setQuietName] = useState(profile.name);
  // Synchronous twin of `editing` for the document listener and the focusout timer.
  const editingRef = useRef(false);
  const refocusHit = useRef(false);
  const blurTimer = useRef<number>();
  const latest = useRef({ profile, onRename });
  latest.current = { profile, onRename };

  const startEdit = useCallback((): void => {
    if (editingRef.current) {
      return;
    }
    editingRef.current = true;
    setMenu((current) => (current.open ? { ...current, open: false } : current));
    setQuietName(latest.current.profile.name);
    setEditing(true);
  }, []);

  const finishEdit = useCallback((save: boolean, refocus: boolean): void => {
    if (!editingRef.current) {
      return;
    }
    editingRef.current = false;
    window.clearTimeout(blurTimer.current);
    const draft = inputRef.current?.value;
    const { profile: current, onRename: rename } = latest.current;
    refocusHit.current = refocus;
    setEditing(false);
    if (save && draft !== undefined && draft !== current.name) {
      const name = normalizeProxyProfileName(draft);
      if (name !== current.name) {
        rename(current, name);
      }
    }
  }, []);

  // Opened: the name is selected for typing over. Closed by a key or Cancel/Save: back to the card.
  useLayoutEffect(() => {
    if (editing) {
      inputRef.current?.focus();
      inputRef.current?.select();
    } else if (refocusHit.current) {
      refocusHit.current = false;
      hitRef.current?.focus({ preventScroll: true });
    }
  }, [editing]);

  // A press anywhere else saves; it isn't swallowed, so it still does what it was aimed at.
  useEffect(() => {
    if (!editing) {
      return undefined;
    }
    const handlePointerDown = (event: PointerEvent): void => {
      const target = event.target;
      if (target instanceof Node && (inputRef.current?.contains(target) || editActsRef.current?.contains(target))) {
        return;
      }
      finishEdit(true, false);
    };
    document.addEventListener("pointerdown", handlePointerDown, true);
    return () => document.removeEventListener("pointerdown", handlePointerDown, true);
  }, [editing, finishEdit]);

  // A card on its way out (or gone) drops the edit without saving.
  useEffect(() => {
    if (leaving && editingRef.current) {
      editingRef.current = false;
      setEditing(false);
    }
  }, [leaving]);
  useEffect(
    () => () => {
      editingRef.current = false;
      window.clearTimeout(blurTimer.current);
    },
    []
  );

  const handleFocusOut = (): void => {
    if (!editingRef.current) {
      return;
    }
    window.clearTimeout(blurTimer.current);
    // Decide once focus has landed. Another app, or a dialog or menu over the page,
    // keeps the editor open (a dialog hands focus back when it closes).
    blurTimer.current = window.setTimeout(() => {
      if (!editingRef.current || !document.hasFocus()) {
        return;
      }
      const active = document.activeElement;
      if (active?.closest(".overlay, [data-popover]")) {
        return;
      }
      if (!articleRef.current?.contains(active)) {
        finishEdit(true, false);
      }
    }, 0);
  };

  const handleNameKeyDown = (event: KeyboardEvent<HTMLInputElement>): void => {
    // Enter and Esc also confirm or cancel an IME composition; leave those to the IME.
    if (event.nativeEvent.isComposing || event.keyCode === 229) {
      return;
    }
    if (event.key === "Enter" || event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      finishEdit(event.key === "Enter", true);
    }
  };

  const openMenu = (point: { x: number; y: number } | null, returnTo: HTMLElement | null): void => {
    menuReturnRef.current = returnTo;
    setMenu({ open: true, point });
  };

  const handleHitKeyDown = (event: KeyboardEvent<HTMLButtonElement>): void => {
    if (event.key === "F2") {
      event.preventDefault();
      startEdit();
    } else if (event.key === "Delete" || event.key === "Backspace") {
      event.preventDefault();
      onRemove(profile);
    } else if (event.key === "F10" && event.shiftKey) {
      // macOS sends no contextmenu for Shift+F10; elsewhere this keeps it from firing twice.
      event.preventDefault();
      openMenu(null, event.currentTarget);
    }
  };

  const handleContextMenu = (event: MouseEvent<HTMLElement>): void => {
    if (editingRef.current) {
      return;
    }
    event.preventDefault();
    // The Menu key and Shift+F10 carry no pointer position (pointerType "" in Chromium): open under ⋯.
    const keyboard = (event.nativeEvent as Partial<PointerEvent>).pointerType === "" || (event.clientX === 0 && event.clientY === 0);
    if (keyboard) {
      openMenu(null, event.target instanceof HTMLElement && event.target !== articleRef.current ? event.target : hitRef.current);
    } else {
      openMenu({ x: event.clientX, y: event.clientY }, hitRef.current);
    }
  };

  const handleMenuSelect = (action: string): void => {
    if (action === "rename") {
      startEdit();
    } else if (action === "copy") {
      onCopyLink(profile);
    } else if (action === "remove") {
      onRemove(profile);
    }
  };

  const menuItems: ActionMenuItem[] = [
    { id: "rename", label: "Rename", icon: Pencil, shortcut: renameKeyHint ? { label: "F2", aria: "F2" } : undefined },
    { id: "copy", label: "Copy link", icon: Copy },
    { id: "remove", label: "Remove", icon: Trash2, tone: "danger", separatorBefore: true, disabled: view.removeBlocked, note: view.removeNote }
  ];

  return (
    <div className="pf-cell rise" style={{ "--d": 3 + Math.min(index, 9) } as CSSProperties} data-leaving={leaving ? "true" : undefined}>
      <article
        ref={articleRef}
        className="pf-card"
        aria-label={profile.name}
        data-selected={view.selected ? "true" : "false"}
        data-inuse={view.inUse ? "true" : "false"}
        data-gone={profile.isStale ? "true" : "false"}
        data-bad={view.unsupported ? "true" : "false"}
        data-editing={editing ? "true" : undefined}
        onContextMenu={handleContextMenu}
        onBlur={handleFocusOut}
      >
        <button
          ref={hitRef}
          type="button"
          className="pf-hit"
          title={editing ? undefined : view.hitTitle}
          disabled={editing}
          aria-pressed={view.selected}
          aria-disabled={view.unsupported ? true : undefined}
          aria-label={view.hitLabel}
          aria-describedby={view.insecure ? insecureId : undefined}
          aria-keyshortcuts="F2 Shift+F10 Delete"
          onClick={() => onSelect(profile)}
          onKeyDown={handleHitKeyDown}
        />
        <div className="pf-body">
          <div className="pf-head">
            <Badge square tone={view.protoTone}>{view.protocol}</Badge>
            {editing ? (
              <>
                <input
                  ref={inputRef}
                  className="pf-name-input"
                  defaultValue={profile.name}
                  maxLength={MAX_PROXY_PROFILE_NAME_LENGTH}
                  placeholder={RENAME_FIELD_COPY.placeholder}
                  aria-label={RENAME_FIELD_COPY.label}
                  aria-describedby={renameHelpId}
                  title={RENAME_FIELD_COPY.title}
                  spellCheck={false}
                  autoComplete="off"
                  onKeyDown={handleNameKeyDown}
                />
                <span className="sr-only" id={renameHelpId}>
                  {RENAME_FIELD_COPY.help}
                </span>
              </>
            ) : (
              <>
                <span key={profile.name} className={cx("pf-name truncate", profile.name !== quietName && "anim-swap")} title={profile.name}>
                  {profile.name}
                </span>
                {view.badge ? (
                  <Badge tone={view.badge.tone} dot={view.badge.glyph === "dot"} spinner={view.badge.glyph === "spinner"}>
                    {view.badge.text}
                  </Badge>
                ) : null}
              </>
            )}
          </div>
          <span className="pf-addr mono truncate" title={view.address}>
            {view.address}
          </span>
          <div className="pf-tags">
            <span className={cx("pf-tag", view.transportBad && "is-bad")} title="Transport">
              {view.transport}
            </span>
            <span className={cx("pf-tag", view.securityBad && "is-bad")} title="Security">
              {view.security}
            </span>
            {view.insecure ? (
              <span className="pf-tag is-bad" title={view.insecure.text}>
                {view.insecure.tag}
                <span className="sr-only" id={insecureId}>
                  {view.insecure.text}
                </span>
              </span>
            ) : null}
            <span className={cx("pf-src", profile.source === "remote" && "is-public")} title={sourceTitle(profile.source)}>
              <Icon icon={SOURCE_ICON[profile.source]} />
              {sourceLabel(profile.source)}
            </span>
          </div>
          {view.goneText ? (
            <div className="pf-note anim-swap">
              <Badge tone="warn" icon={RefreshCw}>
                Gone from source
              </Badge>
              <span>{view.goneText}</span>
            </div>
          ) : null}
          {view.unsupported ? (
            <div className="pf-note is-warn">
              <Badge tone="warn" icon={TriangleAlert}>
                {view.unsupported.label}
              </Badge>
              <span>{view.unsupported.text}</span>
            </div>
          ) : null}
        </div>
        <div className="pf-foot">
          {state ? (
            <span key={`${profile.id}-${state.label}`} className={cx("pf-state anim-swap", `is-${state.tone}`)}>
              {state.glyph === "dot" ? <StatusDot tone={state.tone === "warn" ? "warn" : "ok"} /> : state.glyph === "spinner" ? <Spinner /> : <Icon icon={Check} />}
              <span className="truncate">{state.label}</span>
            </span>
          ) : editing ? (
            <span className="pf-state" />
          ) : (
            <span className="pf-state pf-hint">
              <span className="truncate">{view.hint}</span>
            </span>
          )}
          {editing ? (
            <span ref={editActsRef} className="pf-edit-acts anim-swap">
              <Button variant="ghost" size="sm" onMouseDown={keepFieldFocus} onClick={() => finishEdit(false, true)}>
                Cancel
              </Button>
              <Button size="sm" onMouseDown={keepFieldFocus} onClick={() => finishEdit(true, true)}>
                Save
              </Button>
            </span>
          ) : (
            <>
              <button type="button" className="pf-pin" aria-pressed={profile.isPinned} title={view.pinTitle} onClick={() => onTogglePin(profile)}>
                <span className="pf-pin-ic" key={profile.isPinned ? "on" : "off"}>
                  <Icon icon={Pin} />
                </span>
                <span>{view.pinLabel}</span>
                <span className="sr-only">{profile.name}</span>
              </button>
              <IconButton
                ref={moreRef}
                icon={Ellipsis}
                label={view.moreLabel}
                tooltip="More actions"
                aria-haspopup="menu"
                aria-expanded={menu.open}
                aria-controls={menu.open ? menuId : undefined}
                onClick={() => {
                  // The menu leaves presses on its anchor alone, so ⋯ toggles it here.
                  if (menu.open) {
                    setMenu((current) => ({ ...current, open: false }));
                  } else {
                    openMenu(null, moreRef.current);
                  }
                }}
              />
            </>
          )}
        </div>
        <ActionMenu
          id={menuId}
          label={view.menuLabel}
          items={menuItems}
          open={menu.open}
          anchorRef={moreRef}
          point={menu.point}
          returnFocusRef={menuReturnRef}
          onSelect={handleMenuSelect}
          onClose={() => setMenu((current) => ({ ...current, open: false }))}
        />
      </article>
    </div>
  );
});
